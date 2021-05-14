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

#include <memory>

#include <cstdint>

namespace retrec {

class syscall_emulator {
public:
    syscall_emulator(Architecture target_arch_);

    std::variant<status_code, SyscallRet> emulate_syscall(int64_t target_number,
                                                          const SyscallParameters &parameters);
private:
    Architecture target_arch;
    std::unique_ptr<syscall_rewriter> rewriter;
};

}
