#pragma once

#include <disassembler.h>

namespace retrec {
class llir_lifter_x86_64 final : public llir_lifter {
    static llir::Operand::Width get_width(uint8_t width);
    void fill_operand(cs_x86_op &op, llir::Operand &out);
    llir::Register get_reg(x86_reg reg);

public:
    llir_lifter_x86_64() {}
    ~llir_lifter_x86_64();
    status_code lift(cs_insn *insn, std::vector<llir::Insn> &out) override;
};

}
