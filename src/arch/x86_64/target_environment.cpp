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

#include <arch/x86_64/target_environment.h>

#include <cstdint>

using namespace retrec;
using namespace retrec::x86_64;

void *x86_64::initialize_target_stack(void *stack, const std::vector<std::string> &argv,
                               const std::vector<std::string> &envp) {
    // Initialize the stack with argc/argv/envp process arguments as expected by an
    // x86_64 linux userspace process. The stack will look like this after we're done:
    //
    // top --> ---------------------
    //        |                     |
    //        |  /* STRING POOL */  | <-
    //        |                     |   |
    //        | ------------------- |   |
    //        |              NULL   |   |
    //        |            envp[n]  | --
    //        | /* envp */   ...    |   |
    //        |            envp[0]  | --
    //        | ------------------- |   |
    //        |              NULL   |   |
    //        |            argv[n]  | --
    //        | /* argv */   ...    |   |
    //        |            argv[0]  | --
    //        | --------------------|
    // sp --> |      /* argc */     |
    //         ---------------------
    //
    uint8_t *sp = (uint8_t *)stack;

    // Dump strings on to the stack first
    std::vector<uint8_t *> argv_offsets;
    for (auto &str : argv) {
        // Copy this string to the stack in reverse
        *(--sp) = '\0';
        for (size_t i = str.size(); i-- > 0;)
            *(--sp) = str[i];

        // Save the offset
        argv_offsets.push_back(sp);
    }

    std::vector<uint8_t *> envp_offsets;
    for (auto &str : envp) {
        // Copy this string to the stack in reverse
        *(--sp) = '\0';
        for (size_t i = str.size(); i-- > 0;)
            *(--sp) = str[i];

        // Save the offset
        envp_offsets.push_back(sp);
    }

    // Align stack to 8 bytes
    sp = (uint8_t *)((uintptr_t)sp & ~0b111);
    uint64_t *sp64 = (uint64_t *)sp;

    // Push envp pointers in reverse
    *(--sp64) = 0;
    for (size_t i = envp_offsets.size(); i-- > 0;) {
        *(--sp64) = (uint64_t)envp_offsets[i];
    }

    // Push argv pointers in reverse
    *(--sp64) = 0;
    for (size_t i = argv_offsets.size(); i-- > 0;) {
        *(--sp64) = (uint64_t)argv_offsets[i];
    }

    // Push argc
    *(--sp64) = argv.size();

    return sp64;
}
