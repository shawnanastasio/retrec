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

#include <virtual_address_mapper.h>
#include <util/util.h>

using namespace retrec;

virtual_address_mapper::virtual_address_mapper() {}

/**
 * insert - Register a {vaddr : haddr} mapping
 */
void virtual_address_mapper::insert(VAddrT vaddr, HAddrT haddr) {
    map.insert({vaddr, haddr});
}

/**
 * Lookup - Find the corresponding haddr for a given vaddr
 */
auto virtual_address_mapper::lookup(VAddrT vaddr) -> HAddrT {
    auto pair_it = map.find(vaddr);
    if (pair_it == map.end())
        return 0;
    return pair_it->second;
}

/**
 * lookup_and_update_call_cache - Find the corresponding haddr for a given vaddr,
 * and update the call cache with the given (vaddr, haddr) pair so it can be quickly
 * looked up by future RETs.
 *
 * Useful for implementing "CALL".
 */
auto virtual_address_mapper::lookup_and_update_call_cache(VAddrT target, VAddrT ret_vaddr,
                                                               HAddrT ret_haddr) -> HAddrT {
    // Try to insert return's address into the call cache
    if (free_cache_entries > 0) {
        for (auto &entry : call_cache) {
            if (!entry.valid) {
                free_cache_entries--;
                entry.valid = true;
                entry.vaddr = ret_vaddr;
                entry.haddr = ret_haddr;
                break;
            }
        }
    }

    // Find the target host address and return it
    auto pair_it = map.find(target);
    if (pair_it == map.end())
        return 0;
    return pair_it->second;
}

/**
 * lookup_check_call_cache - Find the corresponding haddr for a given vaddr,
 * checking the call cache first then falling back to the map.
 *
 * Useful for implementing "RET".
 */
auto virtual_address_mapper::lookup_check_call_cache(VAddrT target) -> HAddrT {
    // Check the call cache
    if (free_cache_entries != CALL_CACHE_SIZE) {
        for (auto &entry : call_cache) {
            if (entry.valid && entry.vaddr == target) {
                // Invalidate the entry and return the haddr. In the future the
                // cache should probably be more clever.
                entry.valid = false;
                free_cache_entries++;
                return entry.haddr;
            }
        }
    }

    // Nothing in the call cache, check the map
    auto pair_it = map.find(target);
    if (pair_it == map.end())
        return 0;
    return pair_it->second;
}
