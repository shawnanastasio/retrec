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

#include <arch/runtime_context_dispatcher.h>
#include <memory>
#include <variant>

using namespace retrec;

runtime_context_dispatcher::runtime_context_dispatcher(CodegenBackend backend) {
    switch (backend) {
#if RETREC_CODEGEN_PPC64LE
        case CodegenBackend::PPC64LE:
            context = runtime_context_ppc64le {};
            break;
#endif

#if RETREC_CODEGEN_GENERIC
        case CodegenBackend::Generic:
            context = runtime_context_generic {};
            break;
#endif
    default:
        ASSERT_NOT_REACHED();
    }
}

status_code runtime_context_dispatcher::init(Architecture target_arch, void *entry, void *stack, virtual_address_mapper *vam,
                                             syscall_emulator *syscall_emu) {

    return std::visit([=](auto &rc) -> status_code {
        if constexpr (!types_are_same_v<decltype(rc), Sentinel<0>>)
            return rc.init(target_arch, entry, stack, vam, syscall_emu);
        else
            ASSERT_NOT_REACHED();
    }, context);
}

status_code runtime_context_dispatcher::execute() {
    return std::visit([](auto &rc) -> status_code {
        if constexpr (!types_are_same_v<decltype(rc), Sentinel<0>>)
            return rc.execute();
        else
            ASSERT_NOT_REACHED();
    }, context);
}

void *runtime_context_dispatcher::get_data() {
    return std::visit([](auto &rc) -> void * {
        if constexpr (!types_are_same_v<decltype(rc), Sentinel<0>>)
            return &rc;
        else
            ASSERT_NOT_REACHED();
    }, context);
}
