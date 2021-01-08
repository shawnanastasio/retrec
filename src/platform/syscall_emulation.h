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

#include <util/util.h>
#include <platform/generic_syscalls.h>

#include <cstdint>

namespace retrec {

class syscall_emulator {
public:
    syscall_emulator(Architecture target) : target_arch(target) {}

    struct SyscallRet {
        int64_t ret;
        bool should_exit;
    };

    SyscallRet emulate_syscall(int64_t number, int64_t arg1, int64_t arg2, int64_t arg3,
                               int64_t arg4, int64_t arg5, int64_t arg6);
private:
    Architecture target_arch;

    GenericSyscall get_generic_syscall_number(int64_t number);
    SyscallRet sys$exit(int64_t arg1);
};

template <typename T>
void init_syscall_emulator(Architecture target) {
    extern syscall_emulator *g_syscall_emulator;
    assert(!g_syscall_emulator);
    g_syscall_emulator = new T(target);
}

static inline syscall_emulator &get_syscall_emulator() {
    extern syscall_emulator *g_syscall_emulator;
    assert(g_syscall_emulator);
    return *g_syscall_emulator;
}

}