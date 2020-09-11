#pragma once

#include <util.h>

namespace retrec {
namespace ppc64le {

using gpr_t = uint8_t;
static constexpr gpr_t GPR_INVALID = (gpr_t)-1;

/**
 * Register allocator for X86_64 targets
 */
class register_allocator_x86_64 {
    // Allocation status of GPRs. True = reserved, false = free.
    struct RegisterInfo {
        enum class State {
            FREE,
            ALLOCATED,
            RESERVED
        } state;
    } gprs[32];

    // Statically allocated GPRs.
    gpr_t reserved_allocations[(size_t)llir::X86_64Register::MAXIMUM - 1];

    bool is_reserved(gpr_t gpr) {
        for (size_t i=0; i<ARRAY_SIZE(reserved_allocations); i++)
            if (reserved_allocations[i] == gpr)
                return true;
        return false;
    }

    // reserved_allocations doesn't reserve space for the invalid register index 0, so subtract 1 to get index
    size_t reserved_index(const llir::Register &reg) { return (size_t)reg.x86_64 - 1; }
    size_t reserved_index(llir::X86_64Register reg) { return (size_t)reg - 1; }

public:
    register_allocator_x86_64() {
        for (size_t i=0; i<ARRAY_SIZE(gprs); i++)
            gprs[i] = { RegisterInfo::State::FREE };

        for (size_t i=0; i<ARRAY_SIZE(reserved_allocations); i++)
            reserved_allocations[i] = GPR_INVALID;

        // Statically allocate some X86_64 registers to GPRs.
        // The static allocations try to match X86_64 SysV calling conventions
        // to ppc64le ELFv2 calling conventions to reduce the save/restore penalty when
        // foreign function calls or syscalls are made.
        //
        // Must be kept in sync with accessors in runtime_context_ppc64le.h
        reserved_allocations[reserved_index(llir::X86_64Register::RDI)] = 3; gprs[3] = {RegisterInfo::State::RESERVED};
        reserved_allocations[reserved_index(llir::X86_64Register::RSI)] = 4; gprs[4] = {RegisterInfo::State::RESERVED};
        reserved_allocations[reserved_index(llir::X86_64Register::RDX)] = 5; gprs[5] = {RegisterInfo::State::RESERVED};
        reserved_allocations[reserved_index(llir::X86_64Register::RCX)] = 6; gprs[6] = {RegisterInfo::State::RESERVED};
        reserved_allocations[reserved_index(llir::X86_64Register::R8)]  = 7; gprs[7] = {RegisterInfo::State::RESERVED};
        reserved_allocations[reserved_index(llir::X86_64Register::R9)]  = 8; gprs[8] = {RegisterInfo::State::RESERVED};
        reserved_allocations[reserved_index(llir::X86_64Register::RAX)] = 9; gprs[9] = {RegisterInfo::State::RESERVED};

        // Store pointer to runtime_context in R11
        gprs[11] = {RegisterInfo::State::RESERVED};
    }

    /// Allocate a register for a given target register, with optional value hint
    gpr_t allocate_gpr_internal(const llir::Register *reg, const int64_t *hint) {
        if (reg) {
            // Check if this register has a reserved static allocation
            gpr_t reserved = reserved_allocations[reserved_index(*reg)];
            if (reserved != GPR_INVALID)
                return reserved;
        }

        // No stipulations
        for (gpr_t i=1 /* skip GPR0 which is sometimes useless */; i<ARRAY_SIZE(gprs); i++) {
            if (gprs[i].state == RegisterInfo::State::FREE) {
                gprs[i].state = RegisterInfo::State::ALLOCATED;
                return i;
            }
        }

        return GPR_INVALID; // No free registers
    }
    gpr_t allocate_gpr(const llir::Register &reg) { return allocate_gpr_internal(&reg, nullptr); }
    gpr_t allocate_gpr() { return allocate_gpr_internal(nullptr, nullptr); }

    void free_gpr(gpr_t gpr) {
        assert(gpr != GPR_INVALID);
        if (gprs[gpr].state == RegisterInfo::State::RESERVED)
            return;
        assert(gprs[gpr].state == RegisterInfo::State::ALLOCATED);
        gprs[gpr].state = RegisterInfo::State::FREE;
    }
};

};
};