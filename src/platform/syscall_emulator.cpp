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
 * GNU Lesser General Public License for more rewriter.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with retrec.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <platform/syscall_emulator.h>
#include <platform/generic_syscalls.h>

#include <arch/x86_64/syscalls.h>
#include <arch/ppc64le/syscalls.h>

#include <unistd.h>
#include <sys/syscall.h>

using namespace retrec;

std::unique_ptr<syscall_rewriter> make_syscall_rewriter(Architecture target_arch) {
    if constexpr (HOST_ARCH_PPC64LE) {
        switch (target_arch) {
#define declare_case(arch, details) \
            case arch: return std::make_unique<syscall_rewriter_linux_ppc64le<details>>();

            ENUMERATE_ALL_LINUX_SYSCALL_DETAILS(declare_case)
#undef declare_case
            default: UNREACHABLE();
        }
    } else {
        TODO();
    }
}

syscall_emulator::syscall_emulator(Architecture target_arch_)
    : target_arch(target_arch_),
      rewriter(make_syscall_rewriter(target_arch)) {}


std::variant<status_code, SyscallRet> syscall_emulator::emulate_syscall(int64_t target_number,
                                                                        const SyscallParameters &parameters) {
    return rewriter->invoke_syscall(target_number, parameters);
}

