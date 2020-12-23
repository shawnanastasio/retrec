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
