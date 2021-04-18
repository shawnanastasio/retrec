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

struct cpu_context_x86_64 {
    int64_t gprs[16] { 0 };
    int64_t segments[6] { 0 }; // Acutally only 16-bit, but made 64-bit for get_reg
    int64_t rip { 0 };

    // x86/MMX registers
    struct x87_reg {
        uint64_t lo { 0 }; // Low 64 bits of x87 register, aliased to MMX MM0-7
        uint16_t hi { 0 };
        uint16_t pad[3] { 0 };
    };
    x87_reg x87[8];
    uint16_t x87_control { 0 };
    uint16_t x87_status { 0 };
    uint16_t x87_tag { 0 };
    uint64_t x87_last_ip { 0 };
    uint64_t x87_last_data_ptr { 0 };
    uint16_t x87_opcode { 0 };

    // Pseudo-register for storing the offset from x87[0] where the stack TOP is, in bytes.
    uint16_t st_top_offset { 7 * sizeof(x87_reg) };

    // SSE registers
    reg128 xmm[16];
    uint32_t mxcsr { 0 };

    template <typename T>
    T *get_reg(llir::X86_64Register reg) {
        switch (reg) {
            case llir::X86_64Register::RAX:
            case llir::X86_64Register::RBX:
            case llir::X86_64Register::RCX:
            case llir::X86_64Register::RDX:
            case llir::X86_64Register::RSP:
            case llir::X86_64Register::RBP:
            case llir::X86_64Register::RSI:
            case llir::X86_64Register::RDI:
            case llir::X86_64Register::R8:
            case llir::X86_64Register::R9:
            case llir::X86_64Register::R10:
            case llir::X86_64Register::R11:
            case llir::X86_64Register::R12:
            case llir::X86_64Register::R13:
            case llir::X86_64Register::R14:
            case llir::X86_64Register::R15:
                if constexpr (types_are_same_v<T, decltype(&gprs[0])>)
                    return &gprs[(size_t)reg - (size_t)llir::X86_64Register::RAX];
                break;

            case llir::X86_64Register::ST0:
            case llir::X86_64Register::ST1:
            case llir::X86_64Register::ST2:
            case llir::X86_64Register::ST3:
            case llir::X86_64Register::ST4:
            case llir::X86_64Register::ST5:
            case llir::X86_64Register::ST6:
            case llir::X86_64Register::ST7:
                if constexpr (types_are_same_v<T*, decltype(&x87[0])>)
                    return &x87[(size_t)reg - (size_t)llir::X86_64Register::ST0];
                break;

            case llir::X86_64Register::XMM0:
            case llir::X86_64Register::XMM1:
            case llir::X86_64Register::XMM2:
            case llir::X86_64Register::XMM3:
            case llir::X86_64Register::XMM4:
            case llir::X86_64Register::XMM5:
            case llir::X86_64Register::XMM6:
            case llir::X86_64Register::XMM7:
            case llir::X86_64Register::XMM8:
            case llir::X86_64Register::XMM9:
            case llir::X86_64Register::XMM10:
            case llir::X86_64Register::XMM11:
            case llir::X86_64Register::XMM12:
            case llir::X86_64Register::XMM13:
            case llir::X86_64Register::XMM14:
            case llir::X86_64Register::XMM15:
                if constexpr (types_are_same_v<T, decltype(&xmm[0])>)
                    return &xmm[(size_t)reg - (size_t)llir::X86_64Register::XMM0];
                break;
            case llir::X86_64Register::MXCSR:
                if constexpr (types_are_same_v<T, decltype(&mxcsr)>)
                    return &mxcsr;
                break;

            case llir::X86_64Register::RIP:
                if constexpr (types_are_same_v<T, decltype(&rip)>)
                    return &rip;
                break;

            case llir::X86_64Register::FS:
            case llir::X86_64Register::GS:
            case llir::X86_64Register::CS:
            case llir::X86_64Register::SS:
            case llir::X86_64Register::DS:
            case llir::X86_64Register::ES:
                if constexpr (types_are_same_v<T, decltype(&segments[0])>)
                    return &segments[(size_t)reg - (size_t)llir::X86_64Register::FS];
                break;

            default:
                break;
        }

        // Unsupported register/mismatched type provided
        ASSERT_NOT_REACHED();
    }
};

}
