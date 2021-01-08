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

    int64_t *get_reg(llir::X86_64Register reg) {
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
                return &gprs[(size_t)reg - (size_t)llir::X86_64Register::RAX];

            case llir::X86_64Register::RIP:
                return &rip;

            case llir::X86_64Register::FS:
            case llir::X86_64Register::GS:
            case llir::X86_64Register::CS:
            case llir::X86_64Register::SS:
            case llir::X86_64Register::DS:
            case llir::X86_64Register::ES:
                return &segments[(size_t)reg - (size_t)llir::X86_64Register::FS];

            default:
                TODO();
        }
    }
};

}

