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

#include <allocators.h>
#include <arch/arch.h>
#include <mapped_file.h>
#include <platform/syscall_emulator.h>
#include <process_memory_map.h>
#include <virtual_address_mapper.h>
#include <util/util.h>

#include <functional>
#include <memory>
#include <vector>
#include <cstddef>

namespace retrec {

// Forward-declare translated_code_region since #including <codegen.h> results in cyclic includes.
class translated_code_region;
class runtime_context_dispatcher;

// Forward-declare elf_loader
class elf_loader;

//
// Configuration of target environment
//
struct target_environment {
    mapped_file binary;
    std::vector<std::string> argv;
    std::vector<std::string> envp;
};

//
// A simple execution context for running in the current process' address space.
//
class execution_context {
    process_memory_map vaddr_map;
    long page_size;
    const target_environment &target_env;
    elf_loader &loader;
    simple_placement_allocator code_allocator;

    std::unique_ptr<retrec::runtime_context_dispatcher> runtime_context;

    static constexpr size_t CODE_REGION_MAX_SIZE = 0x10000 * 32; // 2M ought to be enough for anybody :)
    static constexpr size_t DEFAULT_STACK_SIZE = 0x10000; // 64K default stack

public:
    DISABLE_COPY_AND_MOVE(execution_context)
    execution_context(const target_environment &target_env_, elf_loader &loader_);
    ~execution_context();
    status_code init();

    enum class VaddrLocation {
        LOW, // 0x1000+
        HIGH, // 0x3fff+
    };

    static constexpr process_memory_map::Range HIGH_MEM_RANGE = {0x3fff00000000, 0x7fffffffffff};
    static constexpr process_memory_map::Range LOW_MEM_RANGE  = {0x10000, 0xfffeffff};

    //
    // Accessors
    //
    process_memory_map &map() { return vaddr_map; }
    simple_placement_allocator &get_code_allocator() { return code_allocator; }
    void *get_region_ptr(uint64_t ptr);
    void *runtime_ctx();

    //
    // Functions
    //
    status_code allocate_and_map_vaddr(process_memory_map::Range range, size_t size, int prot, void **region_out);
    status_code allocate_new_stack(size_t size, void **stack_out);
    status_code allocate_region(uint64_t start, size_t len, int prot, void **region_out,
                                process_memory_map::Mapping::Type type = process_memory_map::Mapping::Type::USER);
    status_code protect_region(uint64_t start, size_t len, int prot);
    status_code initialize_runtime_context(Architecture target_arch, void *entry, virtual_address_mapper *vam,
                                           syscall_emulator *syscall_emu);
    status_code enter_translated_code();
};

}
