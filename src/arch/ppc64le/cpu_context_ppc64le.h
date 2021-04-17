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
#include <arch/definitions.h>

#include <cstdint>
#include <cstddef>

namespace retrec {

struct alignas(16) cpu_context_ppc64le {
    int64_t gprs[32] { 0 };
    int64_t lr { 0 };
    int64_t cr { 0 };
    int64_t nip { 0 };

    int64_t _pad0;
    reg128 vsr[64] { { .le = { 0, 0 } } };
    int32_t vrsave { 0 };
};

static_assert(offsetof(cpu_context_ppc64le, vsr) % 16 == 0, "vsr registers not quadword aligned!\n");

}
