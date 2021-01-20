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

#include <disassembler.h>

namespace retrec {
class llir_lifter_x86_64 final : public llir_lifter {
    static llir::Operand::Width get_width(uint8_t width);
    void fill_operand(cs_x86_op &op, llir::Operand &out);
    llir::Register get_reg(x86_reg reg);
    llir::Operand get_reg_op(x86_reg reg);

public:
    llir_lifter_x86_64() {}
    ~llir_lifter_x86_64();
    status_code lift(cs_insn *insn, std::vector<llir::Insn> &out) override;
};

}
