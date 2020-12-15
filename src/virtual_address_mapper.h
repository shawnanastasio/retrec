#pragma once

#include <cstdint>
#include <unordered_map>

namespace retrec {

class virtual_address_mapper {
public:
    using VAddrT = uint64_t; // Target virtual address
    using HAddrT = uint64_t; // Host addres

    virtual_address_mapper();

    void insert(VAddrT vaddr, HAddrT haddr);
    HAddrT lookup(VAddrT vaddr);
    HAddrT lookup_and_update_call_cache(VAddrT target, VAddrT ret_vaddr, HAddrT ret_haddr);
    HAddrT lookup_check_call_cache(VAddrT target);

private:
    // Map of all known vaddr:haddr pairs
    std::unordered_map<VAddrT, HAddrT> map;

    // Cache of vaddr:haddr pairs used for quick call cache resolution
    static constexpr size_t CALL_CACHE_SIZE = 32;
    struct call_cache_entry {
        VAddrT vaddr;
        HAddrT haddr;
        bool valid;
    };
    std::array<call_cache_entry, CALL_CACHE_SIZE> call_cache {};
};

extern virtual_address_mapper g_virtual_address_mapper;

} // namespace retrec
