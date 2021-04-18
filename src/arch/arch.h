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

/**
 * This file defines architecture-specific definitions used for compile-time feature selection.
 */

#pragma once

#define HOST_ARCH_PPC64LE 0
#define HOST_ARCH_X86_64 0

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


