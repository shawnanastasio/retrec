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

#pragma once

#include <arch/arch.h>
#include <arch/generic/runtime_context_generic.h>
#include <arch/ppc64le/runtime_context_ppc64le.h>
#include <codegen.h>

#include <variant>

namespace retrec {

class runtime_context_dispatcher {
    std::variant<
#if RETREC_CODEGEN_GENERIC
        runtime_context_generic,
#endif
#if RETREC_CODEGEN_PPC64LE
        runtime_context_ppc64le,
#endif
        Sentinel<0>
    > context;

public:
    explicit runtime_context_dispatcher(CodegenBackend backend);

    status_code init(Architecture target_arch, void *entry, void *stack, virtual_address_mapper *vam,
                     syscall_emulator *syscall_emu);
    status_code execute();
    void *get_data();
};

}
