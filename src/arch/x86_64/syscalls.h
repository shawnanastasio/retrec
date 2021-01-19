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

#include <platform/generic_syscalls.h>

#include <cstdint>

namespace retrec {

enum class SyscallLinuxX86_64 : int64_t {
#define declare_enum(name, val) \
    name = val,

    ENUMERATE_GENERIC_LINUX_SYSCALLS(declare_enum)
#undef declare_enum
};

struct SyscallDetailsLinuxX86_64 {
    using SyscallNumberT = SyscallLinuxX86_64;

    //
    // Definitions
    //

    // Define architecture-specific type mappings
#define enumerate_type_mappings(x) \
    x(char,                u8_le)  \
    x(short,               s16_le) \
    x(int,                 s32_le) \
    x(long,                s64_le) \
    x(long long,           s64_le) \
    x(unsigned char,       u8_le)  \
    x(unsigned short,      u16_le) \
    x(unsigned int,        u32_le) \
    x(unsigned long,       u64_le) \
    x(unsigned long long,  u64_le) \
    x(void *,              ptr64)  \
    /* Declare aliases for agnostic types */ \
    ENUMERATE_SYSCALL_ARG_TYPES(x)

    // Define signatures of all supported syscalls
#define enumerate_syscalls(x) \
    /* Enumerate common syscalls first */ \
    ENUMERATE_COMMON_SYSCALL_SIGNATURES(x)

#define access_type_a(a, _) a,
#define access_type_b(_, b) sc_types::b,
    MAGIC_GEN_TYPE_TO_TYPE_LOOKUP(enumerate_type_mappings, arch_types, access_type_a, access_type_b)
#undef access_type_a
#undef access_type_b

#define access_enum(e, ...) SyscallLinuxX86_64::e,
#define access_sig(name, ret, ...) SyscallSignature<SyscallLinuxGeneric::name, ret, ##__VA_ARGS__>,
    MAGIC_GEN_ENUM_TO_TYPE_LOOKUP(enumerate_syscalls, signatures_lut, access_enum, access_sig, SyscallNumberT)
#undef access_enum
#undef access_sig

    //
    // Accessors
    //

    // Accessor for retrieving the signature of a syscall
    template <SyscallNumberT syscall>
    using signature_from_syscall = signatures_lut_look_up_type<syscall>;

    // Accessor for retrieving the corresponding agnostic type for a given archtiecture-specific type
    template <typename T>
    using agnostic_type_from_type = arch_types_look_up_type_b<T>;

    //
    // Run-time helpers
    //
    static constexpr int64_t get_generic_syscall_number(int64_t x86_64_syscall_number) { return x86_64_syscall_number; }

#undef enumerate_syscalls
#undef enumerate_type_mappings
};

}
