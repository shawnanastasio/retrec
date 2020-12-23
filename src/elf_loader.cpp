#include <elf_loader.h>

#include <algorithm>
#include <cstdint>
#include <cassert>
#include <cstring>

#include <sys/mman.h>

using namespace retrec;

// Program header constants
constexpr uint32_t PHDR_GNU_RELRO = 0x6474e552;

elf_loader::~elf_loader() {
    if (elf)
        elf_end(elf);
}

status_code elf_loader::init() {
    if (elf_version(EV_CURRENT) == EV_NONE) {
        pr_error("Failed to set ELF version: %s\n", elf_errmsg(-1));
        return status_code::BADELF;
    }

    elf = elf_memory(file.data<char *>(), file.length());
    if (!elf) {
        pr_error("Failed to open ELF file: %s\n", elf_errmsg(-1));
        return status_code::BADELF;
    }

    if (gelf_getehdr(elf, &ehdr) == nullptr) {
        pr_error("Failed to get ELF header: %s\n", elf_errmsg(-1));
        return status_code::BADELF;
    }

    // Validate kind
    Elf_Kind ek = elf_kind(elf);
    if (ek != ELF_K_ELF) {
        pr_error("Unknown ELF kind: %d\n", ek);
        return status_code::BADELF;
    }

    // Validate architecture
    if (ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        pr_error("Only 64-bit binaries are supported!\n");
        return status_code::BADELF;
    }
    switch (ehdr.e_machine) {
        case EM_X86_64:
            arch = Architecture::X86_64;
            break;
        default:
            pr_error("Unsupported target architecture!\n");
            return status_code::BADELF;
    }

    // Comb through section table for .symtab
    Elf_Scn *symtab_scn = nullptr;
    GElf_Shdr symtab_hdr;
    size_t stridx = (size_t)-1;

    size_t shstridx;
    if (elf_getshdrstrndx(elf, &shstridx) != 0)
        return status_code::BADELF;

    Elf_Scn *scn = nullptr;
    size_t i = 1;
    while ((scn = elf_nextscn(elf, scn)) != nullptr) {
        GElf_Shdr shdr;
        if (gelf_getshdr(scn, &shdr) != &shdr)
            return status_code::BADELF;

        char *name = elf_strptr(elf, shstridx, (size_t)shdr.sh_name);
        if (strcmp(name, ".symtab") == 0) {
            symtab_scn = scn;
            symtab_hdr = shdr;
        } else if (strcmp(name, ".strtab") == 0) {
            stridx = i;
        } else if (strcmp(name, ".text") == 0) {
            text_shndx = i;
            text_shdr = shdr;
        }

        pr_info("Got section: %s\n", name);
        i++;
    }

    // Build internal symbol table
    if (!symtab_scn || stridx == (size_t)-1) {
        pr_error("Failed to find symbol/string table(s)!\n");
        return status_code::BADELF;
    }

    size_t num_symbols = symtab_hdr.sh_size / sizeof(Elf64_Sym);
    Elf_Data *elfdata = elf_getdata(symtab_scn, nullptr);
    for (size_t i=0; i<num_symbols; i++) {
        GElf_Sym cur;
        if (gelf_getsym(elfdata, (int)i, &cur) != &cur)
            return status_code::BADELF;

        char *name = elf_strptr(elf, stridx, cur.st_name);
        pr_debug("Got sym: %s : 0x%lx (size=%zu)\n", name, cur.st_value, cur.st_size);

        // Add to symbol table
        symbols.push_back({
            /*.name  = */ name,
            /*.info  = */ cur.st_info,
            /*.other = */ cur.st_other,
            /*.shndx = */ cur.st_shndx,
            /*.value = */ cur.st_value,
            /*.size  = */ cur.st_size,
            /*.bind  = */ (Symbol::Bind)ELF64_ST_BIND(cur.st_info)
        });
    }

    // Sort table
    std::sort(symbols.begin(), symbols.end(), [](auto &a, auto &b) {
        return a.value < b.value;
    });

#if RETREC_MINIMUM_LOG_LEVEL <= _LOGL_DEBUG
    for (auto &e : symbols) {
        pr_debug("%s: %zu (shn: %zu)\n", e.name.c_str(), e.value, e.shndx);
    }
#endif

    return status_code::SUCCESS;
}

status_code elf_loader::load_all() {
    GElf_Phdr phdr;
    size_t num_phdr;
    if (elf_getphdrnum(elf, &num_phdr) != 0)
        return status_code::BADELF;

    for (size_t i=0; i<num_phdr; i++) {
        if (gelf_getphdr(elf, (int)i, &phdr) != &phdr) {
            pr_error("Failed to get program headers: %s\n", elf_errmsg(-1));
            return status_code::BADELF;
        }

        switch (phdr.p_type) {
            case PT_LOAD:
            {
                assert(phdr.p_paddr != 0);

                uint64_t aligned_start = phdr.p_vaddr & (~(getpagesize() - 1));
                uint64_t alignment = phdr.p_vaddr - aligned_start;

                // Load this section into the execution context
                void *region;
                auto res = econtext.allocate_region(aligned_start, phdr.p_memsz + alignment, PROT_READ | PROT_WRITE, &region,
                                                    process_memory_map::Mapping::Type::ELF);
                if (res == status_code::OVERLAP) {
                    pr_error("ELF PT_LOAD overlaps existing region.\n"
                                   "  The target binary was probably compiled with a different\n"
                                   "  max page size from the host system. This won't work.\n");
                    return status_code::BADELF;
                } else if (res != status_code::SUCCESS) {
                    pr_error("Failed to allocate region: %s\n", status_code_str(res));
                    return status_code::BADELF;
                }

                // Copy data
                memcpy((void *)((uint8_t *)region + alignment),
                       file.data<char *>() + phdr.p_offset, phdr.p_filesz);

                // Fill in zeros if required
                size_t fill_size = phdr.p_memsz - phdr.p_filesz;
                if (fill_size) {
                    memset((void *)((uint8_t *)region + alignment + phdr.p_filesz), 0, fill_size);
                }

                // Set protection flags
                int flags = ((phdr.p_flags & PF_R) ? PROT_READ : 0)
                             | ((phdr.p_flags & PF_W) ? PROT_WRITE : 0);
                assert(econtext.protect_region(aligned_start, phdr.p_memsz + alignment, flags) == status_code::SUCCESS);

                pr_info("Loaded PT_LOAD segment at 0x%zx!\n", (uint64_t)region);
                break;
            }

            case PHDR_GNU_RELRO:
                pr_warn("Skipping unimplemented GNU_RELRO program header\n");
                break;

            default:
                pr_error("Don't know how to handle phdr type %d\n", phdr.p_type);
                return status_code::BADELF;
        }
    }

    return status_code::SUCCESS;
}

const elf_loader::Symbol *elf_loader::lookup(uint64_t addr, uint64_t shndx, Symbol::Bind bind, LookupPolicy policy) const {
    const elf_loader::Symbol *match = nullptr;
    for (auto &e : symbols) {
        if (e.shndx != shndx)
            continue;

        if (bind != Symbol::Bind::_ANY && e.bind != bind)
            continue;

        switch (policy) {
            case LookupPolicy::EXACT:
                if (e.value == addr)
                    match = &e;
                break;
            case LookupPolicy::CONTAINS:
                if (e.value <= addr && addr < (e.value + get_symbol_size(e)))
                    match = &e;
                break;
        }
        if (match)
            break;
    }

    return match;
}

uint64_t elf_loader::get_symbol_size(const elf_loader::Symbol &sym) const {
    // Simply return the symbol's size attribute. This is not guaranteed to be present,
    // so callers must take care to ensure that size=0 cases are handled.
    return sym.size;
}

const void *elf_loader::get_symbol_data_ptr(const elf_loader::Symbol &sym) {
    // Since we don't support PIC or anything fancy yet, just get the region from the
    // execution context.
    if (sym.shndx == text_shndx)
        return econtext.get_region_ptr(sym.value);
    else
        assert(0 && "Unimplemented!\n");
}
