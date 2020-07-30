#pragma once

#include <util.h>
#include <llir.h>
#include <disassembler.h>

#include <vector>
#include <optional>

namespace retrec {

class lifted_llir_block {
public:
    enum class Flags : uint32_t {
        FULL_FUNCTION = (1 << 0), // Block is a full function lifted from the target executable
    };

    lifted_llir_block(std::vector<llir::Insn> &&insns_, Flags flags_) : insns(insns_), flags(flags_) {}

    const std::vector<llir::Insn> &get_insns() const { return insns; }
    Flags get_flags() const { return flags; }

private:
    std::vector<llir::Insn> insns;
    Flags flags;
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

class codegen {
public:
    virtual status_code init() = 0;
    virtual status_code translate(const lifted_llir_block& insns, std::optional<translated_code_region> &out) = 0;
};

}
