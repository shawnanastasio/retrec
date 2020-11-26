#pragma once

#include <process_memory_map.h>
#include <util/util.h>
#include <functional>
#include <vector>
#include <cstddef>
#include <unistd.h>
#include <sys/mman.h>

namespace retrec {

class simple_placement_allocator {
    void *region;
    size_t region_size;
    size_t max_size;
    size_t page_size;

    size_t used = 0;
    void *last_allocation;
    size_t last_allocation_size;

    void expand() {
        void *res = mmap((void *)((uint8_t *)region + region_size), page_size,
                         PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE,
                         -1, 0);
        assert(res != (void *)-1);
        region_size += page_size;
    }

public:
    simple_placement_allocator() = default;

    void init(void *region_, size_t region_size_, size_t max_size_);
    void *allocate(size_t size);
    void *reallocate(void *ptr, size_t size);

    void free([[maybe_unused]] void *buffer) { /* Placement allocators can't free */ }
};

class simple_region_writer {
    simple_placement_allocator &allocator;
    void *region;
    size_t region_size;

    size_t region_pos = 0;

public:
    simple_region_writer(simple_placement_allocator &allocator_, void *region_, size_t size_)
        : allocator(allocator_), region(region_), region_size(size_) {}

    void *start() const { return region; }
    size_t size() const { return region_size; }
    size_t pos() const { return region_pos; }
    size_t pos_addr() const { return (size_t)region + region_pos; }
    void set_pos(size_t off) { assert(off <= region_size); region_pos = off; }

    status_code write32(uint32_t val);
    void shrink();
};

}
