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
 * Definitions and helpers for the X86_64 target binary environment
 */
#pragma once

#include <vector>
#include <string>
#include <cstdint>

namespace retrec {
namespace x86_64 {

/**
 * Initialize a stack with the given argv/envp.
 * Returns the decremented stack pointer that should be passed to translated runtime.
 */
void *initialize_target_stack(void *stack, const std::vector<std::string> &argv,
                              const std::vector<std::string> &envp);


struct CpuidResult {
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
};

/**
 * Returns the CPUID(func, subfunc) result for the target CPU
 */
void get_cpuid(uint32_t func, uint32_t subfunc, CpuidResult *res);

}
}
