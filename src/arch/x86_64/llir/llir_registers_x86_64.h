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

