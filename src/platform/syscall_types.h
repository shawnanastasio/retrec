/**
 * Copyright 2021 Shawn Anastasio.
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

/**
 * Definitions of and helpers for architecture-agnostic types, useful for representing
 * syscall parameters in a cross-platform way.
 */

namespace retrec::sc_types {

#define ENUMERATE_SYSCALL_ARG_TYPES(x) \
    x(sc_types::u8_le,  u8_le) \
    x(sc_types::u16_le, u16_le) \
    x(sc_types::u32_le, u32_le) \
    x(sc_types::u64_le, u64_le) \
    x(sc_types::s8_le,  s8_le) \
    x(sc_types::s16_le, s16_le) \
    x(sc_types::s32_le, s32_le) \
    x(sc_types::s64_le, s64_le) \
    x(sc_types::u8_be,  u8_be) \
    x(sc_types::u16_be, u16_be) \
    x(sc_types::u32_be, u32_be) \
    x(sc_types::u64_be, u64_be) \
    x(sc_types::s8_be,  s8_be) \
    x(sc_types::s16_be, s16_be) \
    x(sc_types::s32_be, s32_be) \
    x(sc_types::s64_be, s64_be) \
    x(sc_types::ptr32,  ptr32) \
    x(sc_types::ptr64,  ptr64)

#define declare_type(_, x) struct x {};
    ENUMERATE_SYSCALL_ARG_TYPES(declare_type)
#undef declare_type

};

