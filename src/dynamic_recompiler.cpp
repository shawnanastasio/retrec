/**
 * Copyright 2020-2021 Shawn Anastasio.
 *
 * This file is part of retrec.
 *
 * retrec is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * retrec is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with retrec.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <dynamic_recompiler.h>

using namespace retrec;

status_code dynamic_recompiler::init() {
    auto ret = econtext.init();
    if (ret != status_code::SUCCESS)
        return ret;

    ret = loader.init();
    if (ret != status_code::SUCCESS)
        return ret;

    ret = loader.load_all();
    if (ret != status_code::SUCCESS)
        return ret;

    ret = disasm.init();
    if (ret != status_code::SUCCESS)
        return ret;

    // We have to wait until here to initialize the codegen with
    // the correct architecture detected by the elf loader.
    switch (host) {
        case Architecture::ppc64le:
            gen = make_codegen_ppc64le(loader.target_arch(), econtext, &vam);
            break;
        default:
            TODO();
    }

    ret = gen->init();
    if (ret != status_code::SUCCESS)
        return ret;

    syscall_emu = std::make_unique<syscall_emulator>(loader.target_arch());

    return status_code::SUCCESS;
}

status_code dynamic_recompiler::execute() {
    /**
     * Translate entrypoint
     * Jump to entrypoint
     */

    // Lookup entrypoint's symbol
    auto *entry_symbol = loader.lookup(loader.entrypoint(), loader.text_section_index(), elf_loader::Symbol::Bind::GLOBAL,
                                       elf_loader::LookupPolicy::EXACT);
    if (!entry_symbol) {
        pr_error("Failed to find entrypoint symbol!\n");
        return status_code::BADELF;
    }

    // Translate function
    auto res = translate_elf_function(*entry_symbol);
    if (res != status_code::SUCCESS)
        return res;
    auto &code = *translated_regions.begin();

    // Initialize runtime context with entrypoint as target
    res = econtext.initialize_runtime_context(loader.target_arch(), code.code(), &vam, syscall_emu.get());
    if (res != status_code::SUCCESS) {
        pr_error("Failed to initialize runtime context for translated code!\n");
        return res;
    }

    // Code execution loop
    for (;;) {
        status_code res = econtext.enter_translated_code();
        switch (res) {
            case status_code::HALT:
                // Translated code gracefully exited
                return status_code::SUCCESS;

            case status_code::UNTRANSLATED:
            {
                res = runtime_handle_untranslated_access();
                if (res != status_code::SUCCESS) {
                    pr_error("Failed to handle untranslated access: %s\n", status_code_str(res));
                    return res;
                }
                break;
            }

            default:
                // Other status - return it
                return res;
        }
    }
}

status_code dynamic_recompiler::translate_elf_function(const elf_loader::Symbol &symbol) {
    // Determine length of target routine
    uint64_t func_len = loader.get_symbol_size(symbol);
    if (func_len == 0) {
        // The size attribute isn't present, probably due to hand-written assembly
        // missing a .size directive.
        return translate_raw_code_block(symbol.value);
    }

    pr_debug("function length: %zu\n", func_len);
    const void *code_ptr = loader.get_symbol_data_ptr(symbol);
    if (!code_ptr) {
        pr_error("Failed to get symbol data ptr!\n");
        return status_code::NOMEM;
    }

    // Disassemble
    std::vector<llir::Insn> lifted_insns;
    status_code res = disasm.disassemble_region(code_ptr, func_len, symbol.value, lifted_insns,
                                                disassembler::Mode::FULL_FUNCTION);
    if (res != status_code::SUCCESS) {
        pr_error("Failed to disassemble region!\n");
        return res;
    }

    lifted_llir_block block(std::move(lifted_insns), lifted_llir_block::Flags::FULL_FUNCTION);

    // Translate the routine
    std::optional<translated_code_region> translated_code;
    auto ret = gen->translate(block, translated_code);
    if (ret != status_code::SUCCESS) {
        pr_error("Failed to translate routine!\n");
        return ret;
    }
    translated_regions.push_back(*translated_code);

    return status_code::SUCCESS;
}

status_code dynamic_recompiler::translate_raw_code_block(uint64_t vaddr) {
    // Find the Mapping that the vaddr lies within
    size_t mapping_index;
    auto mapping_opt = econtext.map().find(vaddr, 1, &mapping_index, process_memory_map::FindPolicy::CONTAINS);
    if (!mapping_opt) {
        pr_debug("Unable to find mapping containing target vaddr 0x%lx\n", vaddr);
        return status_code::BADACCESS;
    }
    auto mapping = *mapping_opt;

    size_t max_size = 0;
    // Determine the maximum length of the code buffer by walking the memory map
    // and adding the size of all contiguous memory regions.
    max_size = mapping.end - vaddr;
    for (size_t i = mapping_index + 1; i < econtext.map().size(); i++) {
        auto &cur = econtext.map()[i];
        auto &prev = econtext.map()[i-1];
        if (prev.end != cur.start) {
            // Discontinuity, stop increasing size
            break;
        } else {
            max_size += cur.end;
        }
    }

    pr_debug("Translating raw code region of max size: %zu\n", max_size);

    // Disassemble
    std::vector<llir::Insn> lifted_insns;
    status_code res = disasm.disassemble_region((void *)vaddr, max_size, vaddr, lifted_insns,
                                                disassembler::Mode::PARTIAL);
    if (res != status_code::SUCCESS) {
        pr_error("Failed to disassemble region!\n");
        return res;
    }

    lifted_llir_block block(std::move(lifted_insns), lifted_llir_block::Flags::NONE);

    // Translate the partial routine
    std::optional<translated_code_region> translated_code;
    auto ret = gen->translate(block, translated_code);
    if (ret != status_code::SUCCESS) {
        pr_error("Failed to translate routine!\n");
        return ret;
    }
    translated_regions.push_back(*translated_code);

    return status_code::SUCCESS;
}

/**
 * Translate the code block present at the specified target virtual address.
 * Automatically dispatches to translate_elf_function or translate_raw_code_block
 * as necessary.
 */
status_code dynamic_recompiler::translate_referenced_address(uint64_t address, uint64_t *resolved_out) {
    // See if address is contained within a function in the original ELF binary
    const auto *func_sym = loader.lookup(address, loader.text_section_index(), elf_loader::Symbol::Bind::_ANY,
                                         elf_loader::LookupPolicy::CONTAINS);
    if (func_sym) {
        // Translate the whole function containing the target vaddr
        status_code res = translate_elf_function(*func_sym);
        if (res != status_code::SUCCESS)
            return res;
    } else {
        // The branch target doesn't lie within a function in the original binary, or it
        // does but the function isn't marked with a .size attribute. Treat it as a raw region and
        // lift until the first branch.
        status_code res = translate_raw_code_block(address);
        if (res != status_code::SUCCESS)
            return res;
    }

    // Ensure that the virtual address mapper can now resolve the vaddr
    uint64_t resolved = vam.lookup(address);
    if (!resolved) {
        pr_debug("Couldn't resolve virtual address 0x%lx even after function translation! Bailing out.\n", address);
        return status_code::BADACCESS;
    }
    *resolved_out = resolved;

    return status_code::SUCCESS;
}

/**
 * Handle an access by the translated code to untranslated instructions by
 * first translating the address and then calling into codegen code to patch
 * the access.
 */
status_code dynamic_recompiler::runtime_handle_untranslated_access() {
    void *rctx = (void *)&econtext.runtime_ctx();
    uint64_t referenced_vaddr = gen->get_last_untranslated_access(rctx);

    pr_info("Translating access to virtual address 0x%lx\n", referenced_vaddr);

    // Translate code at referenced address if it isn't already translated
    uint64_t resolved = vam.lookup(referenced_vaddr);
    if (!resolved) {
        status_code res = translate_referenced_address(referenced_vaddr, &resolved);
        if (res != status_code::SUCCESS) {
            pr_error("Failed to resolve reference to virtual address: 0x%lx\n", referenced_vaddr);
            return status_code::BADACCESS;
        }
    }

    // Patch code buffer with reference to newly translated address
    return gen->patch_translated_access(rctx, resolved);
}
