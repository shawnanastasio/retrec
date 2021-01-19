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

#include <platform/generic_syscalls.h>

using namespace retrec;

const char *retrec::generic_linux_syscall_name(SyscallLinuxGeneric number) {
    switch (number) {
#define declare_case(name, _) \
        case SyscallLinuxGeneric::name: return #name;

        ENUMERATE_GENERIC_LINUX_SYSCALLS(declare_case)
#undef declare_case
        default: UNREACHABLE();
    }
}
