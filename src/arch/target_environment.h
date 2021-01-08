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
#include <arch/x86_64/target_environment.h>

#include <vector>
#include <string>

namespace retrec {

static inline void *initialize_target_stack(Architecture target, void *stack,
                                            const std::vector<std::string> &argv,
                                            const std::vector<std::string> &envp) {
    switch (target) {
        case Architecture::X86_64:
            return x86_64::initialize_target_stack(stack, argv, envp);
        default:
            TODO();
    }
}

};
