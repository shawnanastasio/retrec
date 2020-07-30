/**
 * This file defines architecture-specific definitions used for compile-time feature selection.
 */

#pragma once

#define HOST_ARCH_PPC64LE 0
#define HOST_ARCH_X86_64 0

//
// Common definitions
//
extern "C" void arch_enter_translated_code(void *code, void *runtime_context);
extern "C" void arch_leave_translated_code();

//
// Arch detection and dependant inclusion
//
#if defined(__powerpc64__) && defined(__LITTLE_ENDIAN__) && defined(_CALL_ELF) && (_CALL_ELF == 2)

#undef HOST_ARCH_PPC64LE
#define HOST_ARCH_PPC64LE 1

#include <arch/ppc64le/runtime_context_ppc64le.h>

#elif defined(__x86_64__)

#undef HOST_ARCH_X86_64
#define HOST_ARCH_X86_64 1

#else
#error "Unsupported host architecture!"
#endif


