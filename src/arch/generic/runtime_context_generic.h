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
 * Definition for the generic interpreter backend's runtime context
 */

#include <util/util.h>

namespace retrec {

// Forward
class syscall_emulator;
class virtual_address_mapper;

struct runtime_context_generic {
    runtime_context_generic() {}
    status_code init(Architecture target_arch, void *entry, void *stack, virtual_address_mapper *vam_,
                     syscall_emulator *syscall_emu_);
    status_code execute();
};

}
