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
