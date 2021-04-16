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

#include <type_traits>
#ifndef LLIR_ALLOW_INTERNAL_INCLUDE
#error "Don't include this directly! Use llir.h"
#endif

enum class PPC64Register : uint8_t {
    INVALID,

    R0, R1, R2, R3, R4, R5, R6, R7, R8, R9,
    R10, R11, R12, R13, R14, R15, R16, R17,
    R18, R19, R20, R21, R22, R23, R24, R25,
    R26, R27, R28, R29, R30, R31,

    LR,
    CR,
    CTR,
    XER,

    F0, F1, F2, F3, F4, F5, F6, F7, F8, F9,
    F10, F11, F12, F13, F14, F15, F16, F17,
    F18, F19, F20, F21, F22, F23, F24, F25,
    F26, F27, F28, F29, F30, F31,

    FPSCR,

    VR0, VR1, VR2, VR3, VR4, VR5, VR6, VR7, VR8, VR9,
    VR10, VR11, VR12, VR13, VR14, VR15, VR16, VR17,
    VR18, VR19, VR20, VR21, VR22, VR23, VR24, VR25,
    VR26, VR27, VR28, VR29, VR30, VR31,

    VSR0, VSR1, VSR2, VSR3, VSR4, VSR5, VSR6, VSR7, VSR8,
    VSR9, VSR10, VSR11, VSR12, VSR13, VSR14, VSR15, VSR16,
    VSR17, VSR18, VSR19, VSR20, VSR21, VSR22, VSR23, VSR24,
    VSR25, VSR26, VSR27, VSR28, VSR29, VSR30, VSR31,

    VSCR,
    VRSAVE,

    MAXIMUM
};

enum class PPC64RegisterType {
    INVALID,
    GPR,
    SPECIAL,
    FPR,
    VR,
    VSR
};

static constexpr inline PPC64RegisterType PPC64RegisterGetType(PPC64Register reg) {
    auto reg_int = enum_cast(reg);
    if (reg_int >= enum_cast(PPC64Register::R0) && reg_int <= enum_cast(PPC64Register::R31))
        return PPC64RegisterType::GPR;
    else if (reg_int >= enum_cast(PPC64Register::LR) && reg_int <= enum_cast(PPC64Register::XER))
        return PPC64RegisterType::SPECIAL;
    else if (reg_int >= enum_cast(PPC64Register::F0) && reg_int <= enum_cast(PPC64Register::F31))
        return PPC64RegisterType::FPR;
    else if (reg_int >= enum_cast(PPC64Register::VR0) && reg_int <= enum_cast(PPC64Register::VR31))
        return PPC64RegisterType::VR;
    else if (reg_int >= enum_cast(PPC64Register::VSR0) && reg_int <= enum_cast(PPC64Register::VSR31))
        return PPC64RegisterType::VSR;
    else
        return PPC64RegisterType::INVALID;
}

static constexpr inline std::underlying_type_t<PPC64Register> PPC64RegisterGPRIndex(PPC64Register reg) {
    assert(PPC64RegisterGetType(reg) == PPC64RegisterType::GPR);
    return enum_cast(reg) - enum_cast(PPC64Register::R0);
}

static constexpr inline std::underlying_type_t<PPC64Register> PPC64RegisterFPRIndex(PPC64Register reg) {
    assert(PPC64RegisterGetType(reg) == PPC64RegisterType::FPR);
    return enum_cast(reg) - enum_cast(PPC64Register::F0);
}

static constexpr inline std::underlying_type_t<PPC64Register> PPC64RegisterVRIndex(PPC64Register reg) {
    assert(PPC64RegisterGetType(reg) == PPC64RegisterType::VR);
    return enum_cast(reg) - enum_cast(PPC64Register::VR0);
}

static constexpr inline std::underlying_type_t<PPC64Register> PPC64RegisterVSRIndex(PPC64Register reg) {
    assert(PPC64RegisterGetType(reg) == PPC64RegisterType::VSR);
    return enum_cast(reg) - enum_cast(PPC64Register::VSR0);
}
