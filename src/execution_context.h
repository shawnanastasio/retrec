#pragma once

#include <allocators.h>
#include <arch/arch.h>
#include <mapped_file.h>
#include <process_memory_map.h>
#include <util/util.h>

#include <functional>
#include <memory>
#include <vector>
#include <cstddef>

namespace retrec {

// Forward-declare translated_code_region since #including <codegen.h> results in cyclic includes.
class translated_code_region;
struct runtime_context;

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
    simple_placement_allocator code_allocator;

    std::unique_ptr<retrec::runtime_context> runtime_context;

    static constexpr size_t CODE_REGION_MAX_SIZE = 0x10000 * 32; // 2M ought to be enough for anybody :)
    static constexpr size_t DEFAULT_STACK_SIZE = 0x10000; // 64K default stack

public:
    DISABLE_COPY_AND_MOVE(execution_context)
    execution_context(const target_environment &target_env_);
    ~execution_context();
    status_code init();

    enum class VaddrLocation {
        LOW, // 0x1000+
        HIGH, // 0x7fff+
    };

    static constexpr process_memory_map::Range HIGH_MEM_RANGE = {0x7fff00000000, 0x7fffffffffff};
    static constexpr process_memory_map::Range LOW_MEM_RANGE  = {0x10000, 0xfffeffff};

    //
    // Accessors
    //
    process_memory_map &map() { return vaddr_map; }
    simple_placement_allocator &get_code_allocator() { return code_allocator; }
    void *get_region_ptr(uint64_t ptr);
    auto &runtime_ctx() { assert(runtime_context); return *runtime_context; }

    //
    // Functions
    //
    status_code allocate_and_map_vaddr(process_memory_map::Range range, size_t size, int prot, void **region_out);
    status_code allocate_new_stack(size_t size, void **stack_out);
    status_code allocate_region(uint64_t start, size_t len, int prot, void **region_out,
                                process_memory_map::Mapping::Type type = process_memory_map::Mapping::Type::USER);
    status_code protect_region(uint64_t start, size_t len, int prot);
    status_code initialize_runtime_context(Architecture target_arch, void *entry, virtual_address_mapper *vam);
    status_code enter_translated_code();
};

}
