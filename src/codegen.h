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
#include <llir.h>
#include <disassembler.h>

#include <memory>
#include <optional>
#include <vector>

namespace retrec {

class virtual_address_mapper; // Forward

class lifted_llir_block {
public:
    // Declared using struct+enum instead of C++11 scoped enums to allow more
    // ergonomic usage as a bit-field.
    struct Flags {
        enum Type : uint32_t {
            NONE,
            FULL_FUNCTION = (1 << 0), // Block is a full function lifted from the target executable
        };
    };

    lifted_llir_block(std::vector<llir::Insn> &&insns_, Flags::Type flags_) : insns(insns_), flags(flags_) {}

    const std::vector<llir::Insn> &get_insns() const { return insns; }
    Flags::Type get_flags() const { return flags; }

private:
    std::vector<llir::Insn> insns;
    Flags::Type flags;
};

class translated_code_region {
    void *code_buffer;
    size_t code_buffer_size;

public:
    translated_code_region(void *code_buffer_, size_t code_buffer_size_)
        : code_buffer(code_buffer_), code_buffer_size(code_buffer_size_) {}

    void *code() { return code_buffer; }
    size_t size() const { return code_buffer_size; }
};

enum class CodegenBackend {
    Generic,
    PowerPC64LE,
};

constexpr CodegenBackend default_codegen_backend = []{
    if constexpr (RETREC_CODEGEN_PPC64LE)
        return CodegenBackend::PowerPC64LE;
    else if constexpr (RETREC_CODEGEN_GENERIC)
        return CodegenBackend::Generic;
}();

class codegen {
public:
    virtual status_code init() = 0;
    virtual status_code translate(const lifted_llir_block& insns, std::optional<translated_code_region> &out) = 0;
    virtual uint64_t get_last_untranslated_access(void *rctx) = 0;
    virtual status_code patch_translated_access(void *rctx, uint64_t resolved_haddr) = 0;
    virtual ~codegen() {}
};

std::unique_ptr<codegen> make_codegen(CodegenBackend backend, Architecture target_arch, execution_context &econtext,
                                      virtual_address_mapper *vam);

}
