#include <allocators.h>

using namespace retrec;

void simple_placement_allocator::init(void *region_, size_t region_size_, size_t max_size_) {
    region = region_;
    region_size = region_size_;
    max_size = max_size_;
    page_size = (size_t)getpagesize();
    used = 0;
}

void *simple_placement_allocator::allocate(size_t size) {
    if (size > page_size)
        return nullptr;

    if (used + size > region_size) {
        if (used + size > max_size)
            return nullptr;
        else
            expand();
    }

    last_allocation = (void *)((uint8_t *)region + used);
    last_allocation_size = size;

    used += size;

    return last_allocation;
}

void *simple_placement_allocator::reallocate(void *ptr, size_t size) {
    if (ptr != last_allocation) {
        // Placement allocators can't reallocate anything other than the most
        // recent allocation.
        return nullptr;
    }

    if (size >= last_allocation_size) {
        if (used + (size - last_allocation_size) > region_size)
            return nullptr;

        used += (size - last_allocation_size);
        last_allocation_size = size;
        return ptr;
    } else {
        used -= (last_allocation_size - size);
        last_allocation_size = size;
        return ptr;
    }
}

status_code simple_region_writer::write32(uint32_t val) {
    if (region_pos + 4 >= region_size) {
        // Not enough space, try to reallocate. For now, only reallocate just enough space.
        if (!allocator.reallocate(region, region_size + 4))
            return status_code::NOMEM;
        region_size += 4;
    }

    uint32_t *ptr = (uint32_t *)((uint8_t *)region + region_pos);
    *ptr = val;
    region_pos += 4;

    return status_code::SUCCESS;
}

void simple_region_writer::shrink() {
    assert(allocator.reallocate(region, region_pos));
    region_size = region_pos;
}

