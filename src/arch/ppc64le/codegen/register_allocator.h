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
#include <llir.h>

namespace retrec {
namespace ppc64le {

using gpr_t = uint8_t;
using vsr_t = uint8_t;
static constexpr gpr_t GPR_INVALID = (gpr_t)-1;

// RAII wrapper returned by GPR allocations
template <typename RegisterAllocatorT>
class allocated_reg {
    llir::PPC64Register reg;
    RegisterAllocatorT *allocator { nullptr };
    bool fixed { false };

    allocated_reg(llir::PPC64Register reg, RegisterAllocatorT &allocator)
        : reg(reg), allocator(&allocator) {}
    allocated_reg(llir::PPC64Register reg)
        : reg(reg), fixed(true) {}

public:
    allocated_reg() : reg(llir::PPC64Register::INVALID), allocator(nullptr) {}
    static allocated_reg from_host_register(llir::Register host_reg) {
        assert(host_reg.arch == Architecture::ppc64le);
        return allocated_reg { host_reg.ppc64 };
    }
    friend RegisterAllocatorT;

    gpr_t gpr() const { assert(fixed || allocator); return llir::PPC64RegisterGPRIndex(reg); }
    gpr_t vsr() const { assert(fixed || allocator); return llir::PPC64RegisterVSRIndex(reg); }
    explicit operator bool() { return !!allocator; }

    // Only allow moves
    ~allocated_reg() { if (allocator) allocator->free_reg(reg); }
    allocated_reg(const allocated_reg &) = delete;
    allocated_reg &operator= (allocated_reg &) = delete;
    allocated_reg(allocated_reg &&other)
        : reg(other.reg), allocator(std::exchange(other.allocator, nullptr)) {}
    allocated_reg &operator= (allocated_reg &&other) {
        std::swap(reg, other.reg);
        std::swap(allocator, other.allocator);
        return *this;
    }
};

/**
 * Register allocator for X86_64 targets
 */
template <typename TargetTraits>
class register_allocator {
    // Allocation status of GPRs. True = reserved, false = free.
    struct RegisterInfo {
        enum class State {
            FREE,
            ALLOCATED,
            RESERVED
        } state;
    } regs[(size_t)llir::PPC64Register::MAXIMUM - 1];

    // Statically allocated GPRs
    static struct static_allocation_set {
        static_allocation_set();
        using TargetRegisterT = typename TargetTraits::RegisterT;

        // Maps a given x86_64 register to a reserved ppc64 register, if available
        llir::PPC64Register allocations[(size_t)TargetRegisterT::MAXIMUM - 1];

        // allocations doesn't reserve space for the invalid register index 0, so subtract 1 to get index
        //size_t reserved_index(const llir::Register &reg) { return (size_t)reg.x86_64 - 1; /* FIXME: not hardcoded to x86_64 */ }
        size_t reserved_index(const llir::Register &reg);
        size_t reserved_index(TargetRegisterT reg) { return (size_t)reg - 1; }

        bool is_reserved(llir::PPC64Register reg);
    } static_allocations;

public:
    using AllocatedRegT = allocated_reg<register_allocator<TargetTraits>>;
    friend AllocatedRegT;

    register_allocator();
    ~register_allocator();
    DISABLE_COPY_AND_MOVE(register_allocator)

    AllocatedRegT allocate_gpr();
    AllocatedRegT get_fixed_reg(const llir::Register &reg);
    AllocatedRegT get_fixed_reg(typename TargetTraits::RegisterT reg);

private:
    void free_reg(llir::PPC64Register reg);
};

};
};
