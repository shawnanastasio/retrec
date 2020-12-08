#pragma once

#include <arch/arch.h>
#include <util/util.h>
#include <allocators.h>
#include <process_memory_map.h>

#include <functional>
#include <memory>
#include <vector>
#include <cstddef>

namespace retrec {

// Forward-declare translated_code_region since #including <codegen.h> results in cyclic includes.
class translated_code_region;
struct runtime_context;

//
// A simple execution context for running in the current process' address space.
//
class execution_context {
    process_memory_map vaddr_map;
    long page_size;
    simple_placement_allocator code_allocator;

    std::unique_ptr<retrec::runtime_context> runtime_context;

    static constexpr size_t CODE_REGION_MAX_SIZE = 0x10000 * 32; // 2M ought to be enough for anybody :)
    static constexpr size_t DEFAULT_STACK_SIZE = 0x10000; // 64K default stack

public:
    DISABLE_COPY_AND_MOVE(execution_context)
    execution_context();
    ~execution_context();
    status_code init();

    //
    // Accessors
    //
    process_memory_map &map() { return vaddr_map; }
    simple_placement_allocator &get_code_allocator() { return code_allocator; }
    void *get_region_ptr(uint64_t ptr);

    //
    // Functions
    //
    status_code allocate_new_stack(size_t size, void **stack_out);
    status_code allocate_region(uint64_t start, size_t len, int prot, void **region_out);
    status_code protect_region(uint64_t start, size_t len, int prot);
    status_code initialize_runtime_context(Architecture target_arch, translated_code_region *entry);
    void enter_translated_code();
};

}
