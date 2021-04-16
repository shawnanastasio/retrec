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

/**
 * This file contains common definitions for architecture-specific code
 */

#pragma once

#include <stdint.h>

// Entry/exit function pointers emitted by arch-specific code
extern void (*arch_enter_translated_code_ptr)(void *runtime_context);
extern void (*arch_leave_translated_code_ptr)();

// 128 bit register type
struct reg128 {
    union {
        struct {
            int64_t lo, hi;
        } le;

        struct {
            int64_t hi, lo;
        } be;
    };
};

