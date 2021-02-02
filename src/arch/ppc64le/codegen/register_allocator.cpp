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

#include <arch/ppc64le/codegen/register_allocator.h>
#include <arch/ppc64le/codegen/abi.h>

using namespace retrec;
using namespace retrec::ppc64le;

//
// Static allocation manager
//

template <typename T>
typename register_allocator<T>::static_allocation_set register_allocator<T>::static_allocations;

template <typename T>
register_allocator<T>::static_allocation_set::static_allocation_set() {
    for (size_t i=0; i<ARRAY_SIZE(allocations); i++)
        allocations[i] = llir::PPC64Register::INVALID;

    // Statically allocate any registers declared in the TargetABIMapping for X86_64
    for (const auto &pair : TargetABIMapping<T>::fixed_regs) {
        allocations[reserved_index(pair.target)] = pair.host;
    }
}

template <typename T>
size_t register_allocator<T>::static_allocation_set::reserved_index(const llir::Register &) {
    static_assert(!std::is_same_v<T, T>, "Unimplemented static_allocation_set for this target");
}

template <>
size_t register_allocator<TargetTraitsX86_64>::static_allocation_set::reserved_index(const llir::Register &reg) {
    return (size_t)reg.x86_64 - 1; // Subtract 1 to account for first INVALID element
}

template <typename T>
bool register_allocator<T>::static_allocation_set::is_reserved(llir::PPC64Register reg) {
    for (size_t i=0; i<ARRAY_SIZE(allocations); i++)
        if (allocations[i] == reg)
            return true;
    return false;
}

//
// Register allocator
//

template <typename T>
register_allocator<T>::register_allocator() {
    for (size_t i=0; i<ARRAY_SIZE(regs); i++)
        regs[i] = { RegisterInfo::State::FREE };

    // Mark any GPRs declared non-volatile by the Retrec ABI as RESERVED
    for (auto reg : ABIRetrec<T>::non_volatile_regs) {
        regs[(size_t)reg - 1] = { RegisterInfo::State::RESERVED };
    }
}

template <typename T>
register_allocator<T>::~register_allocator() {}

template <typename T>
typename register_allocator<T>::AllocatedRegT register_allocator<T>::allocate_gpr() {
    constexpr size_t FIRST_GPR_INDEX = (size_t)llir::PPC64Register::R0 - 1;
    constexpr size_t LAST_GPR_INDEX = (size_t)llir::PPC64Register::R31 - 1;
    for (size_t i = FIRST_GPR_INDEX + 1 /* skip GPR0 which is sometimes useless */; i <= LAST_GPR_INDEX; i++) {
        if (regs[i].state == RegisterInfo::State::FREE) {
            regs[i].state = RegisterInfo::State::ALLOCATED;
            return register_allocator<T>::AllocatedRegT((llir::PPC64Register)(i + 1), *this);
        }
    }

    ASSERT_NOT_REACHED(); // No free registers
}

template <typename T>
typename register_allocator<T>::AllocatedRegT register_allocator<T>::get_fixed_reg(const llir::Register &reg) {
    auto ret = static_allocations.allocations[static_allocations.reserved_index(reg)];
    assert(ret != llir::PPC64Register::INVALID);
    return register_allocator<T>::AllocatedRegT(ret, *this);
}

template <typename T>
typename register_allocator<T>::AllocatedRegT register_allocator<T>::get_fixed_reg(typename T::RegisterT reg) {
    auto ret = static_allocations.allocations[static_allocations.reserved_index(reg)];
    assert(ret != llir::PPC64Register::INVALID);
    return register_allocator<T>::AllocatedRegT(ret, *this);
}

template <typename T>
void register_allocator<T>::free_reg(llir::PPC64Register reg) {
    assert(reg != llir::PPC64Register::INVALID);
    if (regs[(size_t)reg - 1].state == RegisterInfo::State::RESERVED)
        return;
    assert(regs[(size_t)reg - 1].state == RegisterInfo::State::ALLOCATED);
    regs[(size_t)reg - 1].state = RegisterInfo::State::FREE;
}

// Explicitly instantiate for all supported target traits
template class ppc64le::register_allocator<ppc64le::TargetTraitsX86_64>;
