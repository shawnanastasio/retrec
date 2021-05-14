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

using namespace retrec;

status_code codegen_generic::init() {
    TODO();
}

status_code codegen_generic::translate(const lifted_llir_block &insns, std::optional<translated_code_region> &out) {
    (void)insns;
    (void)out;
    TODO();
}

uint64_t codegen_generic::get_last_untranslated_access(void *rctx) {
    (void)rctx;
    TODO();
}

status_code codegen_generic::patch_translated_access(void *rctx, uint64_t resolved_haddr) {
    (void)rctx;
    (void)resolved_haddr;
    TODO();
}

