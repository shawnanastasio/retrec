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
#include <util/util.h>

#include <cstdint>
#include <cstring>

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


void x86_64::get_cpuid(uint32_t func, uint32_t subfunc, CpuidResult *res) {
    // For now, we just return the values that `qemu-x86_64 -cpu Westmere` does.
    // In the future we'll want to support multiple virtual CPU models selectable
    // at run-time, and the CPUID should reflect that.
    memset(res, 0, sizeof(*res));

    switch (func) {
        case 0x00:
            // GenuineIntel :)
            res->eax = 0x0000000B;
            res->ebx = 0x756E6547;
            res->ecx = 0x6C65746E;
            res->edx = 0x69746E65;
            break;

        case 0x01:
            res->eax = 0x00800F11;
            res->ebx = 0x0F100800;
            res->ecx = 0x7ED8320B;
            res->edx = 0x178BFBFF;
            break;

        case 0x80000000:
            res->eax = 0x80000008;
            res->ebx = 0x756E6547;
            res->ecx = 0x6C65746E;
            res->edx = 0x49656E69;
            break;

        case 0x80000001:
            res->eax = 0x000206C1;
            res->ebx = 0x00000000;
            res->ecx = 0x00000001;
            res->edx = 0x20100800;
            break;

        case 0x80000002:
            res->eax = 0x74736557;
            res->ebx = 0x6572656D;
            res->ecx = 0x36354520;
            res->edx = 0x4C2F7878;
            break;

        case 0x80000003:
            res->eax = 0x78783635;
            res->ebx = 0x3635582F;
            res->ecx = 0x28207878;
            res->edx = 0x6168654E;
            break;

        case 0x80000004:
            res->eax = 0x2D6D656C;
            res->ebx = 0x00002943;
            res->ecx = 0x00000000;
            res->edx = 0x00000000;
            break;

        case 0x80000005:
            res->eax = 0x01FF01FF;
            res->ebx = 0x01FF01FF;
            res->ecx = 0x40020140;
            res->edx = 0x40020140;
            break;

        case 0x80000006:
            res->eax = 0x00000000;
            res->ebx = 0x42004200;
            res->ecx = 0x02008140;
            res->edx = 0x00808140;
            break;

        case 0x80000008:
            res->eax = 0x00003028;
            res->ebx = 0x00000000;
            res->ecx = 0x00000000;
            res->edx = 0x00000000;
            break;

        default:
            pr_info("Unsupported CPUID func 0x%x,0x%x, returning all 0s.\n", func, subfunc);
            break;
    }
}
