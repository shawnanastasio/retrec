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

#include <arch/generic/codegen_generic.h>
#include <arch/ppc64le/codegen/codegen_ppc64le.h>
#include <codegen.h>
#include <execution_context.h>
#include <virtual_address_mapper.h>

using namespace retrec;

std::unique_ptr<codegen> retrec::make_codegen(CodegenBackend backend, Architecture target_arch, execution_context &econtext,
                                              virtual_address_mapper *vam) {
    switch (backend) {
        case CodegenBackend::PowerPC64LE:
            if constexpr (RETREC_CODEGEN_PPC64LE)
                return make_codegen_ppc64le(target_arch, econtext, vam);
            break;

        case CodegenBackend::Generic:
            if constexpr (RETREC_CODEGEN_GENERIC)
                return make_codegen_generic(target_arch, econtext, vam);
            break;
    }

    ASSERT_NOT_REACHED();
}

