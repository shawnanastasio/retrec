#pragma once

#include <disassembler.h>

namespace retrec {
class llir_lifter_x86_64 final : public llir_lifter {
    size_t capstone_handle;

    void fill_operand(cs_x86_op &op, llir::Operand &out);
    llir::Register get_reg(x86_reg reg);
public:
    llir_lifter_x86_64(size_t capstone_handle_) : capstone_handle(capstone_handle_) {}
    status_code lift(cs_insn *insn, std::vector<llir::Insn> &out) override;
};

}