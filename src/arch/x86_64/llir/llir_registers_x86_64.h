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

#ifndef LLIR_ALLOW_INTERNAL_INCLUDE
#error "Don't include this directly! Use llir.h"
#endif

enum class X86_64Register {
    // Used to indicate failure for functions that return an X86_64Register, OR to indicate
    // that this field should be discarded.
    INVALID,

    RAX, RBX, RCX, RDX,
    RSP, RBP, RSI, RDI,
    R8, R9, R10, R11, R12, R13, R14, R15,

    RIP,

    FS, GS, CS, SS, DS, ES,

    MAXIMUM,
};

