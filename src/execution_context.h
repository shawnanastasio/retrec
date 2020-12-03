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

class execution_context {
public:
    virtual status_code init() = 0;
    virtual process_memory_map &map() = 0;
    virtual status_code allocate_region(uint64_t start, size_t len, int prot, void **region_out) = 0;
    virtual status_code protect_region(uint64_t start, size_t len, int prot) = 0;
    virtual void *get_region_ptr(uint64_t ptr) = 0;
    virtual simple_placement_allocator &get_code_allocator() = 0;
    virtual status_code initialize_runtime_context(Architecture target_arch, translated_code_region *entry) = 0;
    virtual void enter_translated_code() = 0;
    virtual ~execution_context() {};
};

//
// A simple execution context for running in the current process' address space.
//
class simple_execution_context final : public execution_context {
    process_memory_map vaddr_map;
    simple_placement_allocator code_allocator;

    std::unique_ptr<retrec::runtime_context> runtime_context;

    static constexpr size_t CODE_REGION_MAX_SIZE = 0x10000 * 32; // 2M ought to be enough for anybody :)

public:
    DISABLE_COPY_AND_MOVE(simple_execution_context)
    simple_execution_context();
    ~simple_execution_context();

    status_code init() override;
    process_memory_map &map() override { return vaddr_map; }
    status_code allocate_region(uint64_t start, size_t len, int prot, void **region_out) override;
    status_code protect_region(uint64_t start, size_t len, int prot) override;
    void *get_region_ptr(uint64_t ptr) override;
    simple_placement_allocator &get_code_allocator() override { return code_allocator; }
    status_code initialize_runtime_context(Architecture target_arch, translated_code_region *entry) override;
    void enter_translated_code() override;
};

}
