#pragma once

#include <util.h>
#include <llir.h>

namespace retrec {
namespace ppc64le {

using gpr_t = uint8_t;
static constexpr gpr_t GPR_INVALID = (gpr_t)-1;

/**
 * Register allocator for X86_64 targets
 */
class register_allocator_x86_64 {
    uint64_t start_vaddr; // Address (in target vaddr space) that allocation starts at (inclusive)
    uint64_t end_vaddr;   // Address (in target vaddr space) that allocation ends at (inclusive)

    // Allocation status of GPRs. True = reserved, false = free.
    struct RegisterInfo {
        enum class State {
            FREE,
            ALLOCATED,
            RESERVED
        } state;
    } gprs[32];

    // Statically allocated GPRs
    static struct static_allocation_set {
        static_allocation_set();

        // Maps a given x86_64 register to a reserved ppc64le register, if available
        gpr_t allocations[(size_t)llir::X86_64Register::MAXIMUM - 1];

        // allocations doesn't reserve space for the invalid register index 0, so subtract 1 to get index
        size_t reserved_index(const llir::Register &reg) { return (size_t)reg.x86_64 - 1; }
        size_t reserved_index(llir::X86_64Register reg) { return (size_t)reg - 1; }

        bool is_reserved(gpr_t gpr) {
            for (size_t i=0; i<ARRAY_SIZE(allocations); i++)
                if (allocations[i] == gpr)
                    return true;
            return false;
        }
    } static_allocations;

public:
    register_allocator_x86_64(uint64_t start_vaddr_);
    ~register_allocator_x86_64();
    //DISABLE_COPY_AND_MOVE(register_allocator_x86_64)

    uint64_t start() const { return start_vaddr; }
    uint64_t end() const { return end_vaddr; }
    void set_end(uint64_t end) { end_vaddr = end; }

    gpr_t allocate_gpr();
    gpr_t get_fixed_gpr(const llir::Register &reg);

    void free_gpr(gpr_t gpr);
};

};
};
