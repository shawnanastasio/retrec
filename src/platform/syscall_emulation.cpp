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

#include <platform/syscall_emulation.h>
#include <platform/generic_syscalls.h>

#include <arch/x86_64/syscalls.h>
#include <arch/ppc64le/syscalls.h>

#include <unistd.h>
#include <sys/syscall.h>

using namespace retrec;

namespace retrec {
syscall_emulator *g_syscall_emulator;
}

syscall_emulator::SyscallRet syscall_emulator::emulate_syscall(int64_t number, int64_t arg1,
                                                               int64_t arg2, int64_t arg3,
                                                               int64_t arg4, int64_t arg5, int64_t arg6) {
    GenericSyscall generic_number = get_generic_syscall_number(number);
    switch (generic_number) {
        case GenericSyscall::read:
        case GenericSyscall::write:
        {
            // Directly pass the call to the kernel
            long res = syscall(host_from_generic_syscall(generic_number), arg1, arg2, arg3, arg4, arg5, arg6);
            return {res, false};
        }

        case GenericSyscall::exit:
            return sys$exit(arg1);

        default:
            TODO();
    }
}

GenericSyscall syscall_emulator::get_generic_syscall_number(int64_t number) {
    switch (target_arch) {
        case Architecture::X86_64:
            return to_generic_syscall((X86_64Syscall)number);
        default:
            TODO();
    }
}

syscall_emulator::SyscallRet syscall_emulator::sys$exit(int64_t arg1) {
    // Don't actually exit, just signal an exit to the caller
    return { arg1, true };
}