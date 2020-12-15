#pragma once

#include <type_traits>
#ifndef LLIR_ALLOW_INTERNAL_INCLUDE
#error "Don't include this directly! Use llir.h"
#endif

enum class PPC64Register : uint8_t {
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

    VSCR,
    VRSAVE,

    MAXIMUM
};

enum class PPC64RegisterType {
    GPR,
    SPECIAL,
    FPR,
    VR,
    INVALID
};

static constexpr inline PPC64RegisterType PPC64RegisterGetType(PPC64Register reg) {
    auto reg_int = enum_cast(reg);
    if (reg_int >= enum_cast(PPC64Register::R0) && reg_int <= enum_cast(PPC64Register::R31))
        return PPC64RegisterType::GPR;
    else if (reg_int >= enum_cast(PPC64Register::LR) && reg_int <= enum_cast(PPC64Register::XER))
        return PPC64RegisterType::SPECIAL;
    else if (reg_int >= enum_cast(PPC64Register::F0) && reg_int <= enum_cast(PPC64Register::FPSCR))
        return PPC64RegisterType::FPR;
    else if (reg_int >= enum_cast(PPC64Register::VR0) && reg_int <= enum_cast(PPC64Register::VRSAVE))
        return PPC64RegisterType::VR;
    else
        return PPC64RegisterType::INVALID;
}

static constexpr inline std::underlying_type_t<PPC64Register> PPC64RegisterGPRIndex(PPC64Register reg) {
    assert(PPC64RegisterGetType(reg) == PPC64RegisterType::GPR);
    return enum_cast(reg) - enum_cast(PPC64Register::R0);
}

