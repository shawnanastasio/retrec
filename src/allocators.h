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
