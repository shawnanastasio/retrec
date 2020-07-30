#pragma once

#ifndef LLIR_ALLOW_INTERNAL_INCLUDE
#error "Don't include this directly! Use llir.h"
#endif

struct X86_64MemOp {
    Register segment;
    Register base;
    Register index;
    uint8_t scale;
    int64_t disp;
};