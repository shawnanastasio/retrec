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

#include <llir.h>

#include <cstdint>
#include <cstddef>

namespace retrec {

struct cpu_context_ppc64le {
    int64_t gprs[32];
    int64_t lr;
    int64_t cr;
    int64_t nip;

    int64_t fprs[32];

    int64_t _pad0;
    int64_t vmx[12 * 2];
    int32_t vrsave;
};

static_assert(offsetof(cpu_context_ppc64le, vmx) % 16 == 0, "VMX registers not quadword aligned!\n");

}