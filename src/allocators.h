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
    size_t used { 0 };

public:
    void init(void *region_, size_t region_size_);

    void *allocate(size_t size);
    void free([[maybe_unused]] void *buffer) { /* Placement allocators can't free */ }
};

}
