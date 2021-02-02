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

struct cpu_context_x86_64 {
    int64_t gprs[16];
    int64_t segments[6]; // Acutally only 16-bit, but made 64-bit for get_reg
    int64_t rip;

    // SSE registers
    struct xmm_reg {
        int64_t lo, hi;
    };
    xmm_reg xmm[16];
    uint32_t mxcsr;

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
                if constexpr (std::is_same_v<T, decltype(&gprs[0])>)
                    return &gprs[(size_t)reg - (size_t)llir::X86_64Register::RAX];
                goto fail;

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
                if constexpr (std::is_same_v<T, decltype(&xmm[0])>)
                    return &xmm[(size_t)reg - (size_t)llir::X86_64Register::XMM0];
                goto fail;
            case llir::X86_64Register::MXCSR:
                if constexpr (std::is_same_v<T, decltype(&mxcsr)>)
                    return &mxcsr;
                goto fail;

            case llir::X86_64Register::RIP:
                if constexpr (std::is_same_v<T, decltype(&rip)>)
                    return &rip;
                goto fail;

            case llir::X86_64Register::FS:
            case llir::X86_64Register::GS:
            case llir::X86_64Register::CS:
            case llir::X86_64Register::SS:
            case llir::X86_64Register::DS:
            case llir::X86_64Register::ES:
                if constexpr (std::is_same_v<T, decltype(&segments[0])>)
                    return &segments[(size_t)reg - (size_t)llir::X86_64Register::FS];
                goto fail;

            fail:
            default:
                ASSERT_NOT_REACHED();
        }
    }
};

}

