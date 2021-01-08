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

#include <array>
#include <unordered_map>
#include <cstdint>

namespace retrec {

/**
 * virtual_address_mapper - Collection of known target virtual address to host address mappings.
 *
 * Entries are inserted by host codegen routines and looked up by translated code, either through
 * native function calls to member functions or via direct member access in emitted code.
 */
class virtual_address_mapper {
public:
    using VAddrT = uint64_t; // Target virtual address
    using HAddrT = uint64_t; // Host addres

    virtual_address_mapper();

    void insert(VAddrT vaddr, HAddrT haddr);
    HAddrT lookup(VAddrT vaddr);
    HAddrT lookup_and_update_call_cache(VAddrT target, VAddrT ret_vaddr, HAddrT ret_haddr);
    HAddrT lookup_check_call_cache(VAddrT target);

    struct call_cache_entry {
        uint64_t valid; // Boolean but 64 bits for easy access from assembly
        VAddrT vaddr;
        HAddrT haddr;
    };
    static constexpr size_t CALL_CACHE_SIZE = 32;

    //
    // Member variables
    //

    // Map of all known vaddr:haddr pairs
    std::unordered_map<VAddrT, HAddrT> map;

    // Cache of vaddr:haddr pairs used for quick call cache resolution
    size_t free_cache_entries { CALL_CACHE_SIZE };
    call_cache_entry call_cache[CALL_CACHE_SIZE] = {{0, 0, 0}};
};

} // namespace retrec
