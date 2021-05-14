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
 * Class definition for generic (interpreter) codegen backend.
 */

#include <codegen.h>

namespace retrec {

class codegen_generic : public codegen {
public:
    status_code init();
    status_code translate(const lifted_llir_block &insns, std::optional<translated_code_region> &out);
    uint64_t get_last_untranslated_access(void *rctx);
    status_code patch_translated_access(void *rctx, uint64_t resolved_haddr);
};

static inline std::unique_ptr<codegen> make_codegen_generic(Architecture, execution_context &, virtual_address_mapper *) {
    TODO();
}

}
