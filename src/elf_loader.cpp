#include <elf_loader.h>

#include <algorithm>
#include <cstdint>
#include <cassert>
#include <cstring>

#include <sys/mman.h>

using namespace retrec;

elf_loader::~elf_loader() {
    if (elf)
        elf_end(elf);
}

status_code elf_loader::init() {
    if (elf_version(EV_CURRENT) == EV_NONE) {
        log(LOGL_ERROR, "Failed to set ELF version: %s\n", elf_errmsg(-1));
        return status_code::BADELF;
    }

    elf = elf_memory(file.data<char *>(), file.length());
    if (!elf) {
        log(LOGL_ERROR, "Failed to open ELF file: %s\n", elf_errmsg(-1));
        return status_code::BADELF;
    }

    if (gelf_getehdr(elf, &ehdr) == nullptr) {
        log(LOGL_ERROR, "Failed to get ELF header: %s\n", elf_errmsg(-1));
        return status_code::BADELF;
    }

    // Validate kind
    Elf_Kind ek = elf_kind(elf);
    if (ek != ELF_K_ELF) {
        log(LOGL_ERROR, "Unknown ELF kind: %d\n", ek);
        return status_code::BADELF;
    }

    // Validate architecture
    if (ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        log(LOGL_ERROR, "Only 64-bit binaries are supported!\n");
        return status_code::BADELF;
    }
    switch (ehdr.e_machine) {
        case EM_X86_64:
            arch = Architecture::X86_64;
            break;
        default:
            log(LOGL_ERROR, "Unsupported target architecture!\n");
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

        log(LOGL_INFO, "Got section: %s\n", name);
        i++;
    }

    // Build internal symbol table
    if (!symtab_scn || stridx == (size_t)-1) {
        log(LOGL_ERROR, "Failed to find symbol/string table(s)!\n");
        return status_code::BADELF;
    }

    size_t num_symbols = symtab_hdr.sh_size / sizeof(Elf64_Sym);
    Elf_Data *elfdata = elf_getdata(symtab_scn, nullptr);
    for (size_t i=0; i<num_symbols; i++) {
        GElf_Sym cur;
        if (gelf_getsym(elfdata, i, &cur) != &cur)
            return status_code::BADELF;

        char *name = elf_strptr(elf, stridx, cur.st_name);
        //log(LOGL_INFO, "Got sym: %s : 0x%x\n", name, cur.st_value);

        // Add to symbol table
        symbols.push_back({
            /*.name  = */ name,
            /*.info  = */ cur.st_info,
            /*.other = */ cur.st_other,
            /*.shndx = */ cur.st_shndx,
            /*.value = */ cur.st_value,
            /*.size  = */ cur.st_size
        });
    }

    // Sort table
    std::sort(symbols.begin(), symbols.end(), [](auto &a, auto &b) {
        return a.value < b.value;
    });

    for (auto &e : symbols) {
        log(LOGL_INFO, "%s: %zu (shn: %zu)\n", e.name.c_str(), e.value, e.shndx);
    }

    return status_code::SUCCESS;
}

status_code elf_loader::load_all() {
    GElf_Phdr phdr;
    size_t num_phdr;
    if (elf_getphdrnum(elf, &num_phdr) != 0)
        return status_code::BADELF;

    for (size_t i=0; i<num_phdr; i++) {
        if (gelf_getphdr(elf, i, &phdr) != &phdr) {
            log(LOGL_ERROR, "Failed to get program headers: %s\n", elf_errmsg(-1));
            return status_code::BADELF;
        }

        switch (phdr.p_type) {
            case PT_LOAD:
            {
                assert(phdr.p_filesz == phdr.p_memsz);
                assert(phdr.p_paddr != 0);

                uint64_t aligned_start = phdr.p_vaddr & (~(getpagesize() - 1));
                uint64_t alignment = phdr.p_vaddr - aligned_start;

                // Load this section into the execution context
                void *region;
                auto res = econtext.allocate_region(aligned_start, phdr.p_memsz + alignment, PROT_READ | PROT_WRITE, &region);
                if (res == status_code::OVERLAP) {
                    log(LOGL_ERROR, "ELF PT_LOAD overlaps existing region.\n"
                                   "  The target binary was probably compiled with a different\n"
                                   "  max page size from the host system. This won't work\n");
                    return status_code::BADELF;
                } else if (res != status_code::SUCCESS) {
                    log(LOGL_ERROR, "Failed to allocate region: %s\n", status_code_str(res));
                    return status_code::BADELF;
                }

                // Copy data
                memcpy((void *)((uint8_t *)region + alignment),
                       file.data<char *>() + phdr.p_offset, phdr.p_filesz);

                // Set protection flags
                int flags = (phdr.p_flags & PF_R) ? PROT_READ : 0
                             | (phdr.p_flags & PF_W) ? PROT_WRITE : 0;
                //           | (phdr.p_flags & PF_X) ? PROT_EXEC : 0 /* ignore execute permission for now */
                assert(econtext.protect_region(aligned_start, phdr.p_memsz + alignment, flags) == status_code::SUCCESS);

                log(LOGL_INFO, "Loaded PT_LOAD segment at 0x%zx!\n", (uint64_t)region);

                break;
            }
            default:
                log(LOGL_ERROR, "Don't know how to handle phdr type %d\n", phdr.p_type);
                return status_code::BADELF;
        }
    }

    return status_code::SUCCESS;
}

const elf_loader::symbol *elf_loader::lookup(uint64_t addr, uint64_t shndx) const {
    const elf_loader::symbol *match = nullptr;
    for (auto &e : symbols) {
        if (e.shndx != shndx)
            continue;

        if (e.value >= addr) {
            match = &e;
            break;
        }
    }

    return match;
}

uint64_t elf_loader::get_symbol_size(const elf_loader::symbol &sym) const {
    // If this symbol has a size, just use that
    if (sym.size > 0)
        return sym.size;

    // Otherwise, use the start of the next symbol as a delimiter, or end of section
    for (auto &e : symbols) {
        // Only include symbols in the current section
        if (e.shndx != sym.shndx)
            continue;

        if (e.value > sym.value) {
            // Found a symbol ahead of us in the address space,
            // Subtract our start from its' and use that as the size.
            return e.value - sym.value;
        }
    }

    // No symbol found, use end of section as delimiter
    return text_shdr.sh_size - (sym.value - text_shdr.sh_addr);
}

const void *elf_loader::get_symbol_data_ptr(const elf_loader::symbol &sym) {
    // Since we don't support PIC or anything fancy yet, just get the region from the
    // execution context.
    if (sym.shndx == text_shndx)
        return econtext.get_region_ptr(sym.value);
    else
        assert(0 && "Unimplemented!\n");
}
