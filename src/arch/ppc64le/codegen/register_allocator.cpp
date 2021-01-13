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
        allocations[i] = GPR_INVALID;

    // Statically allocate any registers declared in the TargetABIMapping for X86_64
    for (const auto &pair : TargetABIMapping<TargetTraitsX86_64>::fixed_regs) {
        allocations[reserved_index(pair.target)] = llir::PPC64RegisterGPRIndex(pair.host);
    }
}

//
// Register allocator
//

template <typename T>
register_allocator<T>::register_allocator() {
    for (size_t i=0; i<ARRAY_SIZE(gprs); i++)
        gprs[i] = { RegisterInfo::State::FREE };

    // Mark any GPRs declared non-volatile by the Retrec ABI as RESERVED
    for (auto reg : ABIRetrec<TargetTraitsX86_64>::non_volatile_regs) {
        if (llir::PPC64RegisterGetType(reg) == llir::PPC64RegisterType::GPR)
            gprs[llir::PPC64RegisterGPRIndex(reg)] = { RegisterInfo::State::RESERVED };
    }
}

template <typename T>
register_allocator<T>::~register_allocator() {}

template <typename T>
typename register_allocator<T>::AllocatedGprT register_allocator<T>::allocate_gpr() {
    for (gpr_t i=1 /* skip GPR0 which is sometimes useless */; i<ARRAY_SIZE(gprs); i++) {
        if (gprs[i].state == RegisterInfo::State::FREE) {
            gprs[i].state = RegisterInfo::State::ALLOCATED;
            return register_allocator<T>::AllocatedGprT(i, this);
        }
    }

    ASSERT_NOT_REACHED(); // No free registers
}

template <typename T>
typename register_allocator<T>::AllocatedGprT register_allocator<T>::get_fixed_gpr(const llir::Register &reg) {
    gpr_t ret = static_allocations.allocations[static_allocations.reserved_index(reg)];
    assert(ret != GPR_INVALID);
    return register_allocator<T>::AllocatedGprT(ret, this);
}

template <typename T>
typename register_allocator<T>::AllocatedGprT register_allocator<T>::get_fixed_gpr(typename T::RegisterT reg) {
    gpr_t ret = static_allocations.allocations[static_allocations.reserved_index(reg)];
    assert(ret != GPR_INVALID);
    return register_allocator<T>::AllocatedGprT(ret, this);
}

template <typename T>
void register_allocator<T>::free_gpr(gpr_t gpr) {
    assert(gpr != GPR_INVALID);
    if (gprs[gpr].state == RegisterInfo::State::RESERVED)
        return;
    assert(gprs[gpr].state == RegisterInfo::State::ALLOCATED);
    gprs[gpr].state = RegisterInfo::State::FREE;
}

// Explicitly instantiate for all supported target traits
template class ppc64le::register_allocator<ppc64le::TargetTraitsX86_64>;
