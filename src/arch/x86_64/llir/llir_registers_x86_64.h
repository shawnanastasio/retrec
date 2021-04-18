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

#define LLIR_ENUMERATE_X86_64_REGISTERS(x) \
    x(INVALID) \
    /* GPRs */\
    x(RAX) \
    x(RBX) \
    x(RCX) \
    x(RDX) \
    x(RSP) \
    x(RBP) \
    x(RSI) \
    x(RDI) \
    x(R8) \
    x(R9) \
    x(R10) \
    x(R11) \
    x(R12) \
    x(R13) \
    x(R14) \
    x(R15) \
    /* x87 regs (absolute address) */\
    x(FR0) \
    x(FR1) \
    x(FR2) \
    x(FR3) \
    x(FR4) \
    x(FR5) \
    x(FR6) \
    x(FR7) \
    /* X87 regs (relative to TOP)*/\
    x(ST0) \
    x(ST1) \
    x(ST2) \
    x(ST3) \
    x(ST4) \
    x(ST5) \
    x(ST6) \
    x(ST7) \
    /* MMX regs */\
    x(MM0) \
    x(MM1) \
    x(MM2) \
    x(MM3) \
    x(MM4) \
    x(MM5) \
    x(MM6) \
    x(MM7) \
    /* SSE regs */\
    x(XMM0) \
    x(XMM1) \
    x(XMM2) \
    x(XMM3) \
    x(XMM4) \
    x(XMM5) \
    x(XMM6) \
    x(XMM7) \
    x(XMM8) \
    x(XMM9) \
    x(XMM10) \
    x(XMM11) \
    x(XMM12) \
    x(XMM13) \
    x(XMM14) \
    x(XMM15) \
    x(MXCSR) \
    /* Instruction pointer */ \
    x(RIP) \
    /* Segments */ \
    x(FS) \
    x(GS) \
    x(CS) \
    x(SS) \
    x(DS) \
    x(ES) \
    x(MAXIMUM)


enum class X86_64Register {
#define declare_enum(x) x,
    LLIR_ENUMERATE_X86_64_REGISTERS(declare_enum)
#undef declare_enum
};

