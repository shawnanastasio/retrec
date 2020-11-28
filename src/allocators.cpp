#include <allocators.h>

using namespace retrec;

void simple_placement_allocator::init(void *region_, size_t region_size_) {
    region = region_;
    region_size = region_size_;
}

void *simple_placement_allocator::allocate(size_t size) {
    if (size > region_size - used) {
        return nullptr;
    } else {
        void *start = (void *)((uint8_t *)region + used);
        used += size;
        return start;
    }
}
