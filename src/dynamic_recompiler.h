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

#pragma once

#include <codegen.h>
#include <disassembler.h>
#include <elf_loader.h>
#include <execution_context.h>
#include <mapped_file.h>
#include <platform/syscall_emulator.h>
#include <virtual_address_mapper.h>
#include <util/util.h>

#include <list>
#include <memory>
#include <string>
#include <variant>
#include <vector>

namespace retrec {

class dynamic_recompiler {
    target_environment target_env;
    execution_context econtext;
    elf_loader loader;
    disassembler disasm;
    CodegenBackend backend = default_codegen_backend;

    std::unique_ptr<codegen> gen;
    std::list<translated_code_region> translated_regions;
    virtual_address_mapper vam;
    std::unique_ptr<syscall_emulator> syscall_emu;

    //
    // Translation helpers
    //
    status_code translate_elf_function(const elf_loader::Symbol &symbol);
    status_code translate_raw_code_block(uint64_t vaddr);
    status_code translate_referenced_address(uint64_t address, uint64_t *resolved_out);
    status_code runtime_handle_untranslated_access();

public:
    dynamic_recompiler(target_environment target_env_) :
        target_env(std::move(target_env_)),
        econtext(target_env, loader),
        loader(econtext, target_env_.binary),
        disasm(loader)
    {
    }

    //
    // Public functions
    //
    status_code init();
    status_code execute();
};

}

