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

#include <util/util.h>

#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include <cstdint>

namespace retrec {

class process_memory_map {
public:
    struct Mapping {
        uint64_t start; // inclusive
        uint64_t end;   // exclusive

        enum class Type {
            SYSTEM, // Allocated by the system/runtime
            USER,   // Allocated by us
            ELF,    // Part of the mapped target ELF
        } type;

        int prot;

        Mapping(uint64_t start_, uint64_t end_, Type type_)
            : start(start_), end(end_), type(type_) {}
        Mapping(uint64_t start_, uint64_t end_, Type type_, int prot_)
            : start(start_), end(end_), type(type_), prot(prot_) {}
    };

    struct Range {
        uint64_t low;  // inclusive
        uint64_t high; // exclusive
    };

    enum class FindPolicy {
        EXACT,    // Exact matches only
        CONTAINS, // addr is within [start, end)
    };

    explicit process_memory_map(pid_t pid_);
    status_code init();

    // Accessors for internal map
    const auto &operator[](size_t i) const { return map[i]; }
    auto size() const { return map.size(); }

    uint64_t allocate_vaddr_in_range(size_t size, Range range);
    void mark_allocated(Mapping entry);
    std::optional<Mapping> find(uint64_t addr, uint64_t len, size_t *index_out, FindPolicy = FindPolicy::EXACT);
    void free(uint64_t addr, uint64_t len);

private:
    pid_t pid;
    long page_size;
    std::vector<Mapping> map;

    void sort();
};

}
