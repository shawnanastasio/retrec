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

#include "llir.h"
#include <arch/x86_64/llir/llir_lifter_x86_64.h>

#include <cstring>

using namespace retrec;

static bool contains_group(cs_detail *detail, x86_insn_group group) {
    for (size_t i=0; detail->groups_count; i++) {
        if (detail->groups[i] == group)
            return true;
    }
    return false;
}

static inline void relative_jump_fixup(llir::Insn &llinsn) {
    if (llinsn.src[0].type() == llir::Operand::Type::IMM && llinsn.branch().target == llir::Branch::Target::RELATIVE) {
        // Annoyingly, capstone will automatically calculate the absolute address for immediate
        // relative jumps, so we have to subtract the instruction's address to undo this and
        // get the original relative offset.
        llinsn.src[0].imm() -= llinsn.address;
    }
}

llir_lifter_x86_64::~llir_lifter_x86_64() {}

status_code llir_lifter_x86_64::lift(cs_insn *insn, std::vector<llir::Insn> &out) {
    cs_detail *detail = insn->detail;
    llir::Insn llinsn;
    llinsn.address = insn->address;
    llinsn.size = insn->size;
    llir::Qualification::Repeat *repeat_qual = nullptr;

    // Miscellaneous information used by *_common code paths to differentiate instructions
    llir::Extension extension = llir::Extension::NONE;
    llir::Register::Mask op_mask;
    llir::Register::TypeHint op_type_hint;
    enum class ZeroOthersMode {
        DONT_TOUCH,
        TRUE,
        FALSE
    };
    ZeroOthersMode zero_others_move_reg {};
    ZeroOthersMode zero_others_load {};
    bool last_access_hint { false };
    bool require_alignment;

    using Flag = llir::Alu::Flag;
    using Mask = llir::Register::Mask;
    using TypeHint = llir::Register::TypeHint;

    auto new_qualification = [&]() -> auto & {
        assert(llinsn.qualification_count < llinsn.qualifications.size());
        return llinsn.qualifications[llinsn.qualification_count++];
    };

    // Decode instruction prefixes
    switch (insn->detail->x86.prefix[0]) {
        case X86_PREFIX_LOCK:
            new_qualification().memory_attribute().atomic = true;
            break;

        case X86_PREFIX_REPE /* Also REP */:
        case X86_PREFIX_REPNE:
            // Add a Repeat qualification and populate the first exit condition with
            // RegisterEmpty(RCX) (or ECX if the 67H prefix is present).
            repeat_qual = &new_qualification().repeat();
            llir::Register exit_register = get_reg(X86_REG_RCX);
            if (insn->detail->x86.prefix[3] == X86_PREFIX_ADDRSIZE)
                exit_register = get_reg(X86_REG_ECX);

            auto register_exit_cond = llir::Qualification::Repeat::ExitCondition::RegisterEmpty { exit_register };
            repeat_qual->exit_conditions[0] = {
                llir::Qualification::Repeat::ExitCondition::EvaluationOrder::BEFORE,
                std::move(register_exit_cond)
            };

            // On each iteration of the loop, decrement the exit register
            repeat_qual->update = {{
                llir::Qualification::Repeat::Update::RegisterDecrement { exit_register }
            }};
            break;
    }

    // Decode instruction from ID
    switch (insn->id) {
        //
        // Branch
        //

        case X86_INS_JMP:
            llinsn.branch().op = llir::Branch::Op::UNCONDITIONAL;
            llinsn.branch().target = contains_group(detail, X86_GRP_BRANCH_RELATIVE)
                                    ? llir::Branch::Target::RELATIVE
                                    : llir::Branch::Target::ABSOLUTE;
            llinsn.dest_cnt = 0;
            llinsn.src_cnt = 1;
            fill_operand(detail->x86.operands[0], llinsn.src[0]);
            relative_jump_fixup(llinsn);

            break;

        case X86_INS_CALL:
            assert(detail->x86.op_count == 1);
            // Model CALL as a JMP with linkage=1 and dest = qword ptr [sp]
            llinsn.branch().op = llir::Branch::Op::UNCONDITIONAL;
            llinsn.branch().target = contains_group(detail, X86_GRP_BRANCH_RELATIVE)
                                    ? llir::Branch::Target::RELATIVE
                                    : llir::Branch::Target::ABSOLUTE;
            llinsn.branch().linkage = true;
            llinsn.dest_cnt = 1;
            llinsn.src_cnt = 1;

            // Create an X86_64MemOp with base=(RSP), disp=(-8), update=PRE as the destination
            llinsn.dest[0].memory().x86_64().base = get_reg(X86_REG_RSP);
            llinsn.dest[0].memory().x86_64().disp = -8;
            llinsn.dest[0].memory().x86_64().segment = get_reg(X86_REG_INVALID);
            llinsn.dest[0].memory().x86_64().index = get_reg(X86_REG_INVALID);
            llinsn.dest[0].memory().x86_64().scale = 1;
            llinsn.dest[0].memory().update = llir::MemOp::Update::PRE;
            llinsn.dest[0].width = llir::Operand::Width::_32BIT;

            fill_operand(detail->x86.operands[0], llinsn.src[0]);
            relative_jump_fixup(llinsn);
            break;

        case X86_INS_RET:
            // Model RET as a JMP to qword ptr [sp]
            llinsn.branch().op = llir::Branch::Op::UNCONDITIONAL;
            llinsn.branch().target = llir::Branch::Target::ABSOLUTE;
            llinsn.dest_cnt = 0;
            llinsn.src_cnt = 1;

            // Create an X86_64MemOp with base=(RSP), disp=(8), update=POST as the source
            llinsn.src[0].memory().x86_64().base = get_reg(X86_REG_RSP);
            llinsn.src[0].memory().x86_64().disp = 8;
            llinsn.src[0].memory().x86_64().segment = get_reg(X86_REG_INVALID);
            llinsn.src[0].memory().x86_64().index = get_reg(X86_REG_INVALID);
            llinsn.src[0].memory().x86_64().scale = 1;
            llinsn.src[0].memory().update = llir::MemOp::Update::POST;
            llinsn.src[0].width = llir::Operand::Width::_64BIT;
            break;

        case X86_INS_JAE:   llinsn.branch().op = llir::Branch::Op::NOT_CARRY; goto jcc_common;
        case X86_INS_JA:    llinsn.branch().op = llir::Branch::Op::X86_ABOVE; goto jcc_common;
        case X86_INS_JBE:   llinsn.branch().op = llir::Branch::Op::X86_BELOW_EQ; goto jcc_common;
        case X86_INS_JB:    llinsn.branch().op = llir::Branch::Op::CARRY; goto jcc_common;
        case X86_INS_JCXZ:  TODO();
        case X86_INS_JECXZ: TODO();
        case X86_INS_JE:    llinsn.branch().op = llir::Branch::Op::EQ; goto jcc_common;
        case X86_INS_JGE:   llinsn.branch().op = llir::Branch::Op::X86_GREATER_EQ; goto jcc_common;
        case X86_INS_JG:    llinsn.branch().op = llir::Branch::Op::X86_GREATER; goto jcc_common;
        case X86_INS_JLE:   llinsn.branch().op = llir::Branch::Op::X86_LESS_EQ; goto jcc_common;
        case X86_INS_JL:    llinsn.branch().op = llir::Branch::Op::X86_LESS; goto jcc_common;
        case X86_INS_JNE:   llinsn.branch().op = llir::Branch::Op::NOT_EQ; goto jcc_common;
        case X86_INS_JNO:   llinsn.branch().op = llir::Branch::Op::NOT_OVERFLOW; goto jcc_common;
        case X86_INS_JNP:   TODO();
        case X86_INS_JNS:   llinsn.branch().op = llir::Branch::Op::NOT_NEGATIVE; goto jcc_common;
        case X86_INS_JO:    llinsn.branch().op = llir::Branch::Op::OVERFLOW; goto jcc_common;
        case X86_INS_JP:    TODO();
        case X86_INS_JRCXZ: TODO();
        case X86_INS_JS:    llinsn.branch().op = llir::Branch::Op::NEGATIVE; goto jcc_common;
        jcc_common:
            llinsn.branch().target = contains_group(detail, X86_GRP_BRANCH_RELATIVE)
                                    ? llir::Branch::Target::RELATIVE
                                    : llir::Branch::Target::ABSOLUTE;
            llinsn.dest_cnt = 0;
            llinsn.src_cnt = 1;
            fill_operand(detail->x86.operands[0], llinsn.src[0]);
            relative_jump_fixup(llinsn);

            break;

        //
        // ALU
        //

        case X86_INS_ADD: llinsn.alu().op = llir::Alu::Op::ADD; llinsn.dest_cnt = 1; goto alu_addsub_2op_common;
        case X86_INS_CMP: llinsn.alu().op = llir::Alu::Op::SUB; llinsn.dest_cnt = 0; goto alu_addsub_2op_common;
        case X86_INS_SUB: llinsn.alu().op = llir::Alu::Op::SUB; llinsn.dest_cnt = 1; goto alu_addsub_2op_common;
        alu_addsub_2op_common:
            assert(detail->x86.op_count == 2);
            llinsn.src_cnt = 2;
            llinsn.alu().modifies_flags = true;
            llinsn.alu().flags_modified = llir::Alu::all_flags;
            fill_operand(detail->x86.operands[0], llinsn.src[0]);
            fill_operand(detail->x86.operands[1], llinsn.src[1]);
            if (llinsn.dest_cnt)
                fill_operand(detail->x86.operands[0], llinsn.dest[0]);

            break;

        case X86_INS_AND:  llinsn.alu().op = llir::Alu::Op::AND; llinsn.dest_cnt = 1; goto alu_bitwise_2op_common;
        case X86_INS_TEST: llinsn.alu().op = llir::Alu::Op::AND; llinsn.dest_cnt = 0; goto alu_bitwise_2op_common;
        case X86_INS_OR:   llinsn.alu().op = llir::Alu::Op::OR;  llinsn.dest_cnt = 1; goto alu_bitwise_2op_common;
        case X86_INS_XOR:  llinsn.alu().op = llir::Alu::Op::XOR; llinsn.dest_cnt = 1; goto alu_bitwise_2op_common;
        alu_bitwise_2op_common:
            assert(detail->x86.op_count == 2);
            llinsn.src_cnt = 2;
            llinsn.alu().modifies_flags = true;
            llinsn.alu().flags_modified = llir::Alu::all_flags;
            llinsn.alu().flags_cleared = {Flag::CARRY, Flag::OVERFLOW};
            fill_operand(detail->x86.operands[0], llinsn.src[0]);
            fill_operand(detail->x86.operands[1], llinsn.src[1]);
            if (llinsn.dest_cnt)
                fill_operand(detail->x86.operands[0], llinsn.dest[0]);

            break;

        case X86_INS_INC: llinsn.alu().op = llir::Alu::Op::ADD; goto incdec_common;
        case X86_INS_DEC: llinsn.alu().op = llir::Alu::Op::SUB; goto incdec_common;
        incdec_common:
            assert(detail->x86.op_count == 1);
            llinsn.src_cnt = 2;
            llinsn.dest_cnt = 1;
            llinsn.alu().modifies_flags = true;
            llinsn.alu().flags_modified = {Flag::OVERFLOW, Flag::SIGN, Flag::ZERO, Flag::AUXILIARY_CARRY, Flag::PARITY};

            fill_operand(detail->x86.operands[0], llinsn.dest[0]);
            fill_operand(detail->x86.operands[0], llinsn.src[0]);
            llinsn.src[1].imm() = 1;
            llinsn.src[1].width = llir::Operand::Width::_64BIT;
            break;

        case X86_INS_NOP:
            llinsn.alu().op = llir::Alu::Op::NOP;
            break;

        case X86_INS_IMUL:
            llinsn.alu().op = llir::Alu::Op::IMUL;
            llinsn.alu().modifies_flags = true;
            llinsn.alu().flags_modified = llir::Alu::all_flags;
            llinsn.alu().flags_undefined = {Flag::SIGN, Flag::ZERO, Flag::AUXILIARY_CARRY, Flag::PARITY};
            switch (detail->x86.op_count) {
                case 1:
                    // One-operand form - OP1*rax -> RDX:RAX
                    llinsn.dest_cnt = 2;
                    llinsn.src_cnt = 2;
                    fill_operand(detail->x86.operands[0], llinsn.src[0]);
                    switch (detail->x86.operands[0].size) {
                        case 1:
                            llinsn.src[1].reg()  = get_reg(X86_REG_AL);
                            llinsn.src[1].width  = llir::Operand::Width::_8BIT;
                            llinsn.dest[0].reg() = get_reg(X86_REG_AL);
                            llinsn.dest[0].width  = llir::Operand::Width::_8BIT;
                            llinsn.dest[1].reg() = get_reg(X86_REG_DL);
                            llinsn.dest[1].width  = llir::Operand::Width::_8BIT;
                            break;
                        case 2:
                            llinsn.src[1].reg()  = get_reg(X86_REG_AX);
                            llinsn.src[1].width  = llir::Operand::Width::_16BIT;
                            llinsn.dest[0].reg() = get_reg(X86_REG_AX);
                            llinsn.dest[0].width  = llir::Operand::Width::_16BIT;
                            llinsn.dest[1].reg() = get_reg(X86_REG_DX);
                            llinsn.dest[1].width  = llir::Operand::Width::_16BIT;
                            break;
                        case 4:
                            llinsn.src[1].reg()  = get_reg(X86_REG_EAX);
                            llinsn.src[1].width  = llir::Operand::Width::_32BIT;
                            llinsn.dest[0].reg() = get_reg(X86_REG_EAX);
                            llinsn.dest[0].width  = llir::Operand::Width::_32BIT;
                            llinsn.dest[1].reg() = get_reg(X86_REG_EDX);
                            llinsn.dest[1].width  = llir::Operand::Width::_32BIT;
                            break;
                        case 8:
                            llinsn.src[1].reg()  = get_reg(X86_REG_RAX);
                            llinsn.src[1].width  = llir::Operand::Width::_64BIT;
                            llinsn.dest[0].reg() = get_reg(X86_REG_RAX);
                            llinsn.dest[0].width  = llir::Operand::Width::_64BIT;
                            llinsn.dest[1].reg() = get_reg(X86_REG_RDX);
                            llinsn.dest[1].width  = llir::Operand::Width::_64BIT;
                            break;
                        default:
                            TODO();
                    }
                    break;
                case 2:
                    // Two-operand form - OP1*OP2 -> OP1
                    llinsn.dest_cnt = 1;
                    llinsn.src_cnt = 2;
                    fill_operand(detail->x86.operands[0], llinsn.dest[0]);
                    fill_operand(detail->x86.operands[0], llinsn.src[0]);
                    fill_operand(detail->x86.operands[1], llinsn.src[1]);
                    break;
                case 3:
                    // Three-operand form - OP2*OP3 -> OP1
                    llinsn.dest_cnt = 1;
                    llinsn.src_cnt = 2;
                    fill_operand(detail->x86.operands[0], llinsn.dest[0]);
                    fill_operand(detail->x86.operands[1], llinsn.src[0]);
                    fill_operand(detail->x86.operands[2], llinsn.src[1]);
                    break;
                default:
                    TODO();
            }
            break;

        case X86_INS_MUL:
            llinsn.alu().op = llir::Alu::Op::MUL;
            llinsn.alu().modifies_flags = true;
            llinsn.alu().flags_modified = llir::Alu::all_flags;
            llinsn.alu().flags_undefined = {Flag::SIGN, Flag::ZERO, Flag::AUXILIARY_CARRY, Flag::PARITY};
            llinsn.src_cnt = 2;

            switch (detail->x86.operands[0].size) {
                case 1:
                    // 8-bit - AL * OP1 -> AX
                    llinsn.dest_cnt = 1;
                    llinsn.dest[0].reg() = get_reg(X86_REG_AX);
                    llinsn.dest[0].width = llir::Operand::Width::_16BIT;
                    llinsn.src[0].reg() = get_reg(X86_REG_AL);
                    llinsn.src[0].width = llir::Operand::Width::_8BIT;
                    fill_operand(detail->x86.operands[0], llinsn.src[1]);
                    break;

                case 2:
                    // 16-bit - AX * OP1 -> DX:AX
                    llinsn.dest_cnt = 2;
                    llinsn.dest[0].reg() = get_reg(X86_REG_AX);
                    llinsn.dest[0].width = llir::Operand::Width::_16BIT;
                    llinsn.dest[1].reg() = get_reg(X86_REG_DX);
                    llinsn.dest[1].width = llir::Operand::Width::_16BIT;
                    llinsn.src[0].reg() = get_reg(X86_REG_AX);
                    llinsn.src[0].width = llir::Operand::Width::_16BIT;
                    fill_operand(detail->x86.operands[0], llinsn.src[1]);
                    break;

                case 4:
                    // 32-bit - EAX * OP1 -> EDX:EAX
                    llinsn.dest_cnt = 2;
                    llinsn.dest[0].reg() = get_reg(X86_REG_EAX);
                    llinsn.dest[0].width = llir::Operand::Width::_32BIT;
                    llinsn.dest[1].reg() = get_reg(X86_REG_EDX);
                    llinsn.dest[1].width = llir::Operand::Width::_32BIT;
                    llinsn.src[0].reg() = get_reg(X86_REG_EAX);
                    llinsn.src[0].width = llir::Operand::Width::_32BIT;
                    fill_operand(detail->x86.operands[0], llinsn.src[1]);
                    break;

                case 8:
                    // 64-bit - RAX * OP1 -> RDX:RAX
                    llinsn.dest_cnt = 2;
                    llinsn.dest[0].reg() = get_reg(X86_REG_RAX);
                    llinsn.dest[0].width = llir::Operand::Width::_64BIT;
                    llinsn.dest[1].reg() = get_reg(X86_REG_RDX);
                    llinsn.dest[1].width = llir::Operand::Width::_64BIT;
                    llinsn.src[0].reg() = get_reg(X86_REG_RAX);
                    llinsn.src[0].width = llir::Operand::Width::_64BIT;
                    fill_operand(detail->x86.operands[0], llinsn.src[1]);
                    break;

                default:
                    TODO();
            }

            break;

        case X86_INS_SAL: llinsn.alu().op = llir::Alu::Op::SHL; goto shift_common;
        case X86_INS_SAR: llinsn.alu().op = llir::Alu::Op::SAR; goto shift_common;
        case X86_INS_SHL: llinsn.alu().op = llir::Alu::Op::SHL; goto shift_common;
        case X86_INS_SHR: llinsn.alu().op = llir::Alu::Op::SHR; goto shift_common;
        shift_common:
            llinsn.src_cnt = 2;
            llinsn.dest_cnt = 1;
            llinsn.alu().modifies_flags = true;
            llinsn.alu().flags_modified = {Flag::CARRY, Flag::SIGN, Flag::ZERO, Flag::AUXILIARY_CARRY};
            fill_operand(detail->x86.operands[0], llinsn.dest[0]);
            fill_operand(detail->x86.operands[0], llinsn.src[0]);
            fill_operand(detail->x86.operands[1], llinsn.src[1]);
            if (detail->x86.operands[1].type == X86_OP_IMM && detail->x86.operands[1].imm == 1) {
                // SAL/SAR/SHL/SHR reg, 1 is a special case and affects the flags differently
                switch (insn->id) {
                    case X86_INS_SAL: // OF = (MSBorig == MSBorig-1)
                    case X86_INS_SHL: // OF = (MSBorig == MSBorig-1)
                    case X86_INS_SHR: // OF = MSBorig
                        llinsn.alu().flags_modified.push_back(Flag::OVERFLOW);
                        break;
                    case X86_INS_SAR: // OF = 0
                        llinsn.alu().flags_cleared.push_back(Flag::OVERFLOW);
                        break;
                }
            } else {
                llinsn.alu().flags_undefined = {Flag::OVERFLOW};
            }
            break;

        case X86_INS_SETA:  llinsn.src[0].branchop() = llir::Branch::Op::X86_ABOVE; goto setcc_common;
        case X86_INS_SETAE: llinsn.src[0].branchop() = llir::Branch::Op::NOT_CARRY; goto setcc_common;
        case X86_INS_SETB:  llinsn.src[0].branchop() = llir::Branch::Op::CARRY; goto setcc_common;
        case X86_INS_SETBE: llinsn.src[0].branchop() = llir::Branch::Op::X86_BELOW_EQ; goto setcc_common;
        case X86_INS_SETE:  llinsn.src[0].branchop() = llir::Branch::Op::EQ; goto setcc_common;
        case X86_INS_SETNE: llinsn.src[0].branchop() = llir::Branch::Op::NOT_EQ; goto setcc_common;
        case X86_INS_SETG:  llinsn.src[0].branchop() = llir::Branch::Op::X86_GREATER; goto setcc_common;
        case X86_INS_SETGE: llinsn.src[0].branchop() = llir::Branch::Op::X86_GREATER_EQ; goto setcc_common;
        case X86_INS_SETL:  llinsn.src[0].branchop() = llir::Branch::Op::X86_LESS; goto setcc_common;
        case X86_INS_SETLE: llinsn.src[0].branchop() = llir::Branch::Op::X86_LESS_EQ; goto setcc_common;
        case X86_INS_SETP:  TODO();
        case X86_INS_SETNP: TODO();
        case X86_INS_SETS:  llinsn.src[0].branchop() = llir::Branch::Op::NEGATIVE; goto setcc_common;
        case X86_INS_SETNS: llinsn.src[0].branchop() = llir::Branch::Op::NOT_NEGATIVE; goto setcc_common;
        case X86_INS_SETO:  llinsn.src[0].branchop() = llir::Branch::Op::OVERFLOW; goto setcc_common;
        case X86_INS_SETNO: llinsn.src[0].branchop() = llir::Branch::Op::NOT_OVERFLOW; goto setcc_common;
        setcc_common:
            llinsn.alu().op = llir::Alu::Op::SETCC;
            llinsn.dest_cnt = 1;
            llinsn.src_cnt  = 1;
            fill_operand(detail->x86.operands[0], llinsn.dest[0]);
            break;

        case X86_INS_CPUID:
            llinsn.alu().op = llir::Alu::Op::X86_CPUID;
            break;

        case X86_INS_STD: llinsn.alu().op = llir::Alu::Op::SETFLAG; llinsn.alu().flags_modified = { Flag::DIRECTION }; break;
        case X86_INS_CLD: llinsn.alu().op = llir::Alu::Op::CLRFLAG; llinsn.alu().flags_modified = { Flag::DIRECTION }; break;
        case X86_INS_STC: llinsn.alu().op = llir::Alu::Op::SETFLAG; llinsn.alu().flags_modified = { Flag::CARRY }; break;
        case X86_INS_CLC: llinsn.alu().op = llir::Alu::Op::CLRFLAG; llinsn.alu().flags_modified = { Flag::CARRY }; break;

        //
        // LoadStore
        //

        case X86_INS_CMOVA:  new_qualification().predicate().condition = llir::Branch::Op::X86_ABOVE; goto mov_common;
        case X86_INS_CMOVAE: new_qualification().predicate().condition = llir::Branch::Op::NOT_CARRY; goto mov_common;
        case X86_INS_CMOVB:  new_qualification().predicate().condition = llir::Branch::Op::CARRY; goto mov_common;
        case X86_INS_CMOVBE: new_qualification().predicate().condition = llir::Branch::Op::X86_BELOW_EQ; goto mov_common;
        case X86_INS_CMOVE:  new_qualification().predicate().condition = llir::Branch::Op::EQ; goto mov_common;
        case X86_INS_CMOVNE: new_qualification().predicate().condition = llir::Branch::Op::NOT_EQ; goto mov_common;
        case X86_INS_CMOVG:  new_qualification().predicate().condition = llir::Branch::Op::X86_GREATER; goto mov_common;
        case X86_INS_CMOVGE: new_qualification().predicate().condition = llir::Branch::Op::X86_GREATER_EQ; goto mov_common;
        case X86_INS_CMOVL:  new_qualification().predicate().condition = llir::Branch::Op::X86_LESS; goto mov_common;
        case X86_INS_CMOVLE: new_qualification().predicate().condition = llir::Branch::Op::X86_LESS_EQ; goto mov_common;
        case X86_INS_CMOVP:  TODO();
        case X86_INS_CMOVNP: TODO();
        case X86_INS_CMOVS:  new_qualification().predicate().condition = llir::Branch::Op::NEGATIVE; goto mov_common;
        case X86_INS_CMOVNS: new_qualification().predicate().condition = llir::Branch::Op::NOT_NEGATIVE; goto mov_common;
        case X86_INS_CMOVO:  new_qualification().predicate().condition = llir::Branch::Op::OVERFLOW; goto mov_common;
        case X86_INS_CMOVNO: new_qualification().predicate().condition = llir::Branch::Op::NOT_OVERFLOW; goto mov_common;
        case X86_INS_MOVZX:  extension = llir::Extension::ZERO; goto mov_common;
        case X86_INS_MOVSX:  extension = llir::Extension::SIGN; goto mov_common;
        case X86_INS_MOVSXD: extension = llir::Extension::SIGN; goto mov_common;
        case X86_INS_LEA:    goto mov_common;
        case X86_INS_MOVABS: goto mov_common;
        case X86_INS_MOV:    goto mov_common;
        mov_common:
            assert(detail->x86.op_count == 2);
            llinsn.dest_cnt = 1;
            llinsn.src_cnt = 1;

            // MOV is pretty epic and can mean a lot of things. Determine what it's doing by looking at operand types
            if (detail->x86.operands[0].type == X86_OP_REG && detail->x86.operands[1].type == X86_OP_IMM) {
                // mov reg, imm - Load Immediate
                llinsn.alu().op = llir::Alu::Op::LOAD_IMM;
                fill_operand(detail->x86.operands[0], llinsn.dest[0]);
                fill_operand(detail->x86.operands[1], llinsn.src[0]);
            } else if (detail->x86.operands[0].type == X86_OP_MEM &&
                       (detail->x86.operands[1].type == X86_OP_REG || detail->x86.operands[1].type == X86_OP_IMM)) {
                // mov mem, {reg,imm} - Store
                llinsn.loadstore().op = llir::LoadStore::Op::STORE;
                fill_operand(detail->x86.operands[0], llinsn.dest[0]);
                fill_operand(detail->x86.operands[1], llinsn.src[0]);
            } else if (detail->x86.operands[0].type == X86_OP_REG && detail->x86.operands[1].type == X86_OP_MEM) {
                // mov reg, mem - Load OR LEA
                llinsn.loadstore().op = (insn->id == X86_INS_LEA) ? llir::LoadStore::Op::LEA : llir::LoadStore::Op::LOAD;
                llinsn.loadstore().extension = extension;
                fill_operand(detail->x86.operands[0], llinsn.dest[0]);
                fill_operand(detail->x86.operands[1], llinsn.src[0]);
            } else if (detail->x86.operands[0].type == X86_OP_REG && detail->x86.operands[1].type == X86_OP_REG) {
                // mov reg, reg, - Move Register
                llinsn.alu().op = llir::Alu::Op::MOVE_REG;
                llinsn.alu().extension = extension;
                fill_operand(detail->x86.operands[0], llinsn.dest[0]);
                fill_operand(detail->x86.operands[1], llinsn.src[0]);
            } else {
                pr_error("Unimplemented MOV type!\n");
                return status_code::UNIMPL_INSN;
            }
            break;

        // <128-bit Legacy SSE MOVs
        case X86_INS_MOVD:
            require_alignment = 0;
            zero_others_move_reg = ZeroOthersMode::TRUE;
            zero_others_load = ZeroOthersMode::TRUE;
            op_mask = Mask::Vector128LowLow32;
            op_type_hint = TypeHint::INT;
            goto mov_legacy_sse_common;

        // 128-bit Legacy SSE MOVs
        case X86_INS_MOVAPD:   require_alignment = 1; op_mask = Mask::Vector128Full; op_type_hint = TypeHint::DOUBLE; goto mov_legacy_sse_common;
        case X86_INS_MOVAPS:   require_alignment = 1; op_mask = Mask::Vector128Full; op_type_hint = TypeHint::FLOAT; goto mov_legacy_sse_common;
        case X86_INS_MOVDQA:   require_alignment = 1; op_mask = Mask::Vector128Full; op_type_hint = TypeHint::INT; goto mov_legacy_sse_common;
        case X86_INS_MOVDQU:   require_alignment = 0; op_mask = Mask::Vector128Full; op_type_hint = TypeHint::INT; goto mov_legacy_sse_common;
        case X86_INS_MOVNTDQ:  require_alignment = 1; op_mask = Mask::Vector128Full; op_type_hint = TypeHint::INT; last_access_hint = true; goto mov_legacy_sse_common;
        case X86_INS_MOVNTDQA: require_alignment = 1; op_mask = Mask::Vector128Full; op_type_hint = TypeHint::INT; last_access_hint = true; goto mov_legacy_sse_common;
        case X86_INS_MOVNTPD:  require_alignment = 1; op_mask = Mask::Vector128Full; op_type_hint = TypeHint::DOUBLE; last_access_hint = true; goto mov_legacy_sse_common;
        case X86_INS_MOVNTPS:  require_alignment = 1; op_mask = Mask::Vector128Full; op_type_hint = TypeHint::FLOAT; last_access_hint = true; goto mov_legacy_sse_common;
        case X86_INS_MOVUPD:   require_alignment = 0; op_mask = Mask::Vector128Full; op_type_hint = TypeHint::DOUBLE; goto mov_legacy_sse_common;
        case X86_INS_MOVUPS:   require_alignment = 0; op_mask = Mask::Vector128Full; op_type_hint = TypeHint::FLOAT; goto mov_legacy_sse_common;
        mov_legacy_sse_common:
            assert(detail->x86.op_count == 2);
            llinsn.dest_cnt = 1;
            llinsn.src_cnt = 1;

            if (detail->x86.operands[0].type == X86_OP_MEM && detail->x86.operands[1].type == X86_OP_REG) {
                // mov mem, xmmN - Store
                llinsn.loadstore().op = llir::LoadStore::Op::VECTOR_STORE;
                llinsn.loadstore().require_alignment = require_alignment;
                llinsn.loadstore().last_access_hint = last_access_hint;
                fill_operand(detail->x86.operands[0], llinsn.dest[0]);
                fill_operand(detail->x86.operands[1], llinsn.src[0]);
                llinsn.src[0].reg().type_hint = op_type_hint;
                llinsn.src[0].reg().mask = op_mask;
            } else if (detail->x86.operands[0].type == X86_OP_REG && detail->x86.operands[1].type == X86_OP_MEM) {
                // mov xmmN, mem - Load
                llinsn.loadstore().op = llir::LoadStore::Op::VECTOR_LOAD;
                llinsn.loadstore().require_alignment = require_alignment;
                llinsn.loadstore().last_access_hint = last_access_hint;
                fill_operand(detail->x86.operands[0], llinsn.dest[0]);
                llinsn.dest[0].reg().type_hint = op_type_hint;
                llinsn.dest[0].reg().mask = op_mask;
                if (zero_others_load != ZeroOthersMode::DONT_TOUCH)
                    llinsn.dest[0].reg().zero_others = zero_others_load == ZeroOthersMode::TRUE;
                fill_operand(detail->x86.operands[1], llinsn.src[0]);
            } else if (detail->x86.operands[0].type == X86_OP_REG && detail->x86.operands[1].type == X86_OP_REG) {
                // mov xmmN, xmmN, - Move Register
                llinsn.alu().op = llir::Alu::Op::MOVE_VECTOR_REG;
                fill_operand(detail->x86.operands[0], llinsn.dest[0]);
                llinsn.dest[0].reg().type_hint = op_type_hint;
                llinsn.dest[0].reg().mask = op_mask;
                if (zero_others_move_reg != ZeroOthersMode::DONT_TOUCH)
                    llinsn.dest[0].reg().zero_others = zero_others_move_reg == ZeroOthersMode::TRUE;
                fill_operand(detail->x86.operands[1], llinsn.src[0]);
                llinsn.src[0].reg().type_hint = op_type_hint;
                llinsn.src[0].reg().mask = op_mask;
            } else {
                pr_error("Unimplemented MOV128 type!\n");
                return status_code::UNIMPL_INSN;
            }

            break;


        case X86_INS_PUSH:
            // Model PUSH as a STORE to RSP-8 + update
            llinsn.dest_cnt = 1;
            llinsn.src_cnt = 1;
            llinsn.loadstore().op = llir::LoadStore::Op::STORE;

            // Create an X86_64MemOp with base=(RSP), disp=(-8), update=PRE as the destination
            llinsn.dest[0].memory().x86_64().base = get_reg(X86_REG_RSP);
            llinsn.dest[0].memory().x86_64().disp = -8;
            llinsn.dest[0].memory().x86_64().segment = get_reg(X86_REG_INVALID);
            llinsn.dest[0].memory().x86_64().index = get_reg(X86_REG_INVALID);
            llinsn.dest[0].memory().x86_64().scale = 1;
            llinsn.dest[0].memory().update = llir::MemOp::Update::PRE;
            llinsn.dest[0].width = llir::Operand::Width::_64BIT;

            // Fill the Source with operand 0
            fill_operand(detail->x86.operands[0], llinsn.src[0]);
            break;

        case X86_INS_POP:
            // Model POP as a LOAD from RSP+8 + update
            llinsn.dest_cnt = 1;
            llinsn.src_cnt = 1;
            llinsn.loadstore().op = llir::LoadStore::Op::LOAD;

            // Create an X86_64MemOp with base=(RSP), disp=(8), update=POST, as the Source
            llinsn.src[0].memory().x86_64().base = get_reg(X86_REG_RSP);
            llinsn.src[0].memory().x86_64().disp = 8;
            llinsn.src[0].memory().x86_64().segment = get_reg(X86_REG_INVALID);
            llinsn.src[0].memory().x86_64().index = get_reg(X86_REG_INVALID);
            llinsn.src[0].memory().x86_64().scale = 1;
            llinsn.src[0].memory().update = llir::MemOp::Update::POST;
            llinsn.src[0].width = llir::Operand::Width::_64BIT;

            // Fill the Destination with operand 0
            fill_operand(detail->x86.operands[0], llinsn.dest[0]);
            break;

        case X86_INS_STOSB: llinsn.dest[0].memory().x86_64().disp = 1; llinsn.src[0] = get_reg_op(X86_REG_AL); goto stos_common;
        case X86_INS_STOSW: llinsn.dest[0].memory().x86_64().disp = 2; llinsn.src[0] = get_reg_op(X86_REG_AX); goto stos_common;
        case X86_INS_STOSD: llinsn.dest[0].memory().x86_64().disp = 4; llinsn.src[0] = get_reg_op(X86_REG_EAX); goto stos_common;
        case X86_INS_STOSQ: llinsn.dest[0].memory().x86_64().disp = 8; llinsn.src[0] = get_reg_op(X86_REG_RAX); goto stos_common;
        stos_common:
            assert(detail->x86.operands[0].type = X86_OP_MEM);
            llinsn.loadstore().op = llir::LoadStore::Op::STORE;
            llinsn.src_cnt = 1;
            llinsn.dest_cnt = 1;
            llinsn.dest[0].memory().x86_64().base = get_reg(detail->x86.operands[0].mem.base);
            llinsn.dest[0].memory().x86_64().segment = get_reg(X86_REG_INVALID);
            llinsn.dest[0].memory().x86_64().index = get_reg(X86_REG_INVALID);
            llinsn.dest[0].memory().x86_64().scale = 1;
            llinsn.dest[0].memory().x86_64().disp_sign_from_df = true;
            llinsn.dest[0].memory().update = llir::MemOp::Update::POST;
            llinsn.dest[0].width = llinsn.src[0].width;
            break;

        //
        // Interrupt
        //

        case X86_INS_SYSCALL:
            llinsn.interrupt().op = llir::Interrupt::Op::SYSCALL;
            llinsn.dest_cnt = 0;
            llinsn.src_cnt = 0;
            break;

        case X86_INS_HLT: goto privileged_common;
        privileged_common:
            // We're a userspace emulator, so treat all privileged instructions as invalid
            llinsn.interrupt().op = llir::Interrupt::Op::ILLEGAL;
            break;


        default:
            return status_code::UNIMPL_INSN;
    }

    // Append instruction to provided vector and return
    out.push_back(llinsn);
    return status_code::SUCCESS;
}


llir::Operand::Width llir_lifter_x86_64::get_width(uint8_t width) {
    switch (width) {
        case 1: return llir::Operand::Width::_8BIT;
        case 2: return llir::Operand::Width::_16BIT;
        case 4: return llir::Operand::Width::_32BIT;
        case 8: return llir::Operand::Width::_64BIT;
        case 16: return llir::Operand::Width::_128BIT;
        default: TODO();
    }
}

void llir_lifter_x86_64::fill_operand(cs_x86_op &op, llir::Operand &out) {
    out.width = get_width(op.size);
    switch (op.type) {
        case X86_OP_IMM:
        {
            int64_t imm = op.imm;

            // Sign extend immediate. This at least allows prettier printing for the llir immediate as an int64_t.
            // Architecture-specific backend code will ignore the extra bits as long as the appropriate register
            // mask is set, so it shouldn't have any effect there.
            if (op.size == 4)
               imm = (int32_t)imm;
            else if (op.size == 2)
               imm = (int16_t)imm;
            else if (op.size == 1)
               imm = (int8_t)imm;

            out.imm() = imm;
            break;
        }
        case X86_OP_MEM:
            out.memory().x86_64().segment = get_reg(op.mem.segment);
            out.memory().x86_64().base = get_reg(op.mem.base);
            out.memory().x86_64().index = get_reg(op.mem.index);
            out.memory().x86_64().scale = (uint8_t)op.mem.scale;
            out.memory().x86_64().disp = op.mem.disp;
            out.memory().update = llir::MemOp::Update::NONE;
            break;

        case X86_OP_REG:
            out.reg() = get_reg(op.reg);
            break;
        default:
            pr_error("Invalid operand type!\n");
            ASSERT_NOT_REACHED();
    }
}

llir::Operand llir_lifter_x86_64::get_reg_op(x86_reg reg) {
    llir::Operand ret;

    ret.reg() = get_reg(reg);
    switch (ret.reg().mask) {
        case llir::Register::Mask::Full64:
            ret.width = llir::Operand::Width::_64BIT;
            break;
        case llir::Register::Mask::Low32:
            ret.width = llir::Operand::Width::_32BIT;
            break;
        case llir::Register::Mask::LowLow16:
            ret.width = llir::Operand::Width::_16BIT;
            break;
        case llir::Register::Mask::LowLowHigh8:
        case llir::Register::Mask::LowLowLow8:
            ret.width = llir::Operand::Width::_8BIT;
            break;
        default: ASSERT_NOT_REACHED();
    }

    return ret;
}

llir::Register llir_lifter_x86_64::get_reg(x86_reg reg) {
    llir::Register ret;
    ret.arch = Architecture::X86_64;
    ret.zero_others = true;

    switch(reg) {
        case X86_REG_INVALID : ret.x86_64 = llir::X86_64Register::INVALID; break;

        // Native 64-bit registers
        case X86_REG_RAX: ret.x86_64 = llir::X86_64Register::RAX; ret.mask = llir::Register::Mask::Full64; break;
        case X86_REG_RBX: ret.x86_64 = llir::X86_64Register::RBX; ret.mask = llir::Register::Mask::Full64; break;
        case X86_REG_RCX: ret.x86_64 = llir::X86_64Register::RCX; ret.mask = llir::Register::Mask::Full64; break;
        case X86_REG_RDX: ret.x86_64 = llir::X86_64Register::RDX; ret.mask = llir::Register::Mask::Full64; break;
        case X86_REG_RSP: ret.x86_64 = llir::X86_64Register::RSP; ret.mask = llir::Register::Mask::Full64; break;
        case X86_REG_RBP: ret.x86_64 = llir::X86_64Register::RBP; ret.mask = llir::Register::Mask::Full64; break;
        case X86_REG_RSI: ret.x86_64 = llir::X86_64Register::RSI; ret.mask = llir::Register::Mask::Full64; break;
        case X86_REG_RDI: ret.x86_64 = llir::X86_64Register::RDI; ret.mask = llir::Register::Mask::Full64; break;
        case X86_REG_R8:  ret.x86_64 = llir::X86_64Register::R8;  ret.mask = llir::Register::Mask::Full64; break;
        case X86_REG_R9:  ret.x86_64 = llir::X86_64Register::R9;  ret.mask = llir::Register::Mask::Full64; break;
        case X86_REG_R10: ret.x86_64 = llir::X86_64Register::R10; ret.mask = llir::Register::Mask::Full64; break;
        case X86_REG_R11: ret.x86_64 = llir::X86_64Register::R11; ret.mask = llir::Register::Mask::Full64; break;
        case X86_REG_R12: ret.x86_64 = llir::X86_64Register::R12; ret.mask = llir::Register::Mask::Full64; break;
        case X86_REG_R13: ret.x86_64 = llir::X86_64Register::R13; ret.mask = llir::Register::Mask::Full64; break;
        case X86_REG_R14: ret.x86_64 = llir::X86_64Register::R14; ret.mask = llir::Register::Mask::Full64; break;
        case X86_REG_R15: ret.x86_64 = llir::X86_64Register::R15; ret.mask = llir::Register::Mask::Full64; break;
        case X86_REG_RIP: ret.x86_64 = llir::X86_64Register::RIP; ret.mask = llir::Register::Mask::Full64; break;

        // 32-bit registers
        case X86_REG_EAX:  ret.x86_64 = llir::X86_64Register::RAX; ret.mask = llir::Register::Mask::Low32; break;
        case X86_REG_EBX:  ret.x86_64 = llir::X86_64Register::RBX; ret.mask = llir::Register::Mask::Low32; break;
        case X86_REG_ECX:  ret.x86_64 = llir::X86_64Register::RCX; ret.mask = llir::Register::Mask::Low32; break;
        case X86_REG_EDX:  ret.x86_64 = llir::X86_64Register::RDX; ret.mask = llir::Register::Mask::Low32; break;
        case X86_REG_ESP:  ret.x86_64 = llir::X86_64Register::RSP; ret.mask = llir::Register::Mask::Low32; break;
        case X86_REG_EBP:  ret.x86_64 = llir::X86_64Register::RBP; ret.mask = llir::Register::Mask::Low32; break;
        case X86_REG_ESI:  ret.x86_64 = llir::X86_64Register::RSI; ret.mask = llir::Register::Mask::Low32; break;
        case X86_REG_EDI:  ret.x86_64 = llir::X86_64Register::RDI; ret.mask = llir::Register::Mask::Low32; break;
        case X86_REG_R8D:  ret.x86_64 = llir::X86_64Register::R8;  ret.mask = llir::Register::Mask::Low32; break;
        case X86_REG_R9D:  ret.x86_64 = llir::X86_64Register::R9;  ret.mask = llir::Register::Mask::Low32; break;
        case X86_REG_R10D: ret.x86_64 = llir::X86_64Register::R10; ret.mask = llir::Register::Mask::Low32; break;
        case X86_REG_R11D: ret.x86_64 = llir::X86_64Register::R11; ret.mask = llir::Register::Mask::Low32; break;
        case X86_REG_R12D: ret.x86_64 = llir::X86_64Register::R12; ret.mask = llir::Register::Mask::Low32; break;
        case X86_REG_R13D: ret.x86_64 = llir::X86_64Register::R13; ret.mask = llir::Register::Mask::Low32; break;
        case X86_REG_R14D: ret.x86_64 = llir::X86_64Register::R14; ret.mask = llir::Register::Mask::Low32; break;
        case X86_REG_R15D: ret.x86_64 = llir::X86_64Register::R15; ret.mask = llir::Register::Mask::Low32; break;

        // 16-bit registers
        case X86_REG_AX:   ret.x86_64 = llir::X86_64Register::RAX; ret.mask = llir::Register::Mask::LowLow16; ret.zero_others = false; break;
        case X86_REG_BX:   ret.x86_64 = llir::X86_64Register::RBX; ret.mask = llir::Register::Mask::LowLow16; ret.zero_others = false; break;
        case X86_REG_CX:   ret.x86_64 = llir::X86_64Register::RCX; ret.mask = llir::Register::Mask::LowLow16; ret.zero_others = false; break;
        case X86_REG_DX:   ret.x86_64 = llir::X86_64Register::RDX; ret.mask = llir::Register::Mask::LowLow16; ret.zero_others = false; break;
        case X86_REG_SP:   ret.x86_64 = llir::X86_64Register::RSP; ret.mask = llir::Register::Mask::LowLow16; ret.zero_others = false; break;
        case X86_REG_BP:   ret.x86_64 = llir::X86_64Register::RBP; ret.mask = llir::Register::Mask::LowLow16; ret.zero_others = false; break;
        case X86_REG_SI:   ret.x86_64 = llir::X86_64Register::RSI; ret.mask = llir::Register::Mask::LowLow16; ret.zero_others = false; break;
        case X86_REG_DI:   ret.x86_64 = llir::X86_64Register::RDI; ret.mask = llir::Register::Mask::LowLow16; ret.zero_others = false; break;
        case X86_REG_R8W:  ret.x86_64 = llir::X86_64Register::R8;  ret.mask = llir::Register::Mask::LowLow16; ret.zero_others = false; break;
        case X86_REG_R9W:  ret.x86_64 = llir::X86_64Register::R9;  ret.mask = llir::Register::Mask::LowLow16; ret.zero_others = false; break;
        case X86_REG_R10W: ret.x86_64 = llir::X86_64Register::R10; ret.mask = llir::Register::Mask::LowLow16; ret.zero_others = false; break;
        case X86_REG_R11W: ret.x86_64 = llir::X86_64Register::R11; ret.mask = llir::Register::Mask::LowLow16; ret.zero_others = false; break;
        case X86_REG_R12W: ret.x86_64 = llir::X86_64Register::R12; ret.mask = llir::Register::Mask::LowLow16; ret.zero_others = false; break;
        case X86_REG_R13W: ret.x86_64 = llir::X86_64Register::R13; ret.mask = llir::Register::Mask::LowLow16; ret.zero_others = false; break;
        case X86_REG_R14W: ret.x86_64 = llir::X86_64Register::R14; ret.mask = llir::Register::Mask::LowLow16; ret.zero_others = false; break;
        case X86_REG_R15W: ret.x86_64 = llir::X86_64Register::R15; ret.mask = llir::Register::Mask::LowLow16; ret.zero_others = false; break;

        // 8-bit registers
        case X86_REG_AH:   ret.x86_64 = llir::X86_64Register::RAX; ret.mask = llir::Register::Mask::LowLowHigh8; ret.zero_others = false; break;
        case X86_REG_BH:   ret.x86_64 = llir::X86_64Register::RBX; ret.mask = llir::Register::Mask::LowLowHigh8; ret.zero_others = false; break;
        case X86_REG_CH:   ret.x86_64 = llir::X86_64Register::RCX; ret.mask = llir::Register::Mask::LowLowHigh8; ret.zero_others = false; break;
        case X86_REG_DH:   ret.x86_64 = llir::X86_64Register::RDX; ret.mask = llir::Register::Mask::LowLowHigh8; ret.zero_others = false; break;
        case X86_REG_AL:   ret.x86_64 = llir::X86_64Register::RAX; ret.mask = llir::Register::Mask::LowLowLow8;  ret.zero_others = false; break;
        case X86_REG_BL:   ret.x86_64 = llir::X86_64Register::RBX; ret.mask = llir::Register::Mask::LowLowLow8;  ret.zero_others = false; break;
        case X86_REG_CL:   ret.x86_64 = llir::X86_64Register::RCX; ret.mask = llir::Register::Mask::LowLowLow8;  ret.zero_others = false; break;
        case X86_REG_DL:   ret.x86_64 = llir::X86_64Register::RDX; ret.mask = llir::Register::Mask::LowLowLow8;  ret.zero_others = false; break;
        case X86_REG_SPL:  ret.x86_64 = llir::X86_64Register::RSP; ret.mask = llir::Register::Mask::LowLowLow8;  ret.zero_others = false; break;
        case X86_REG_BPL:  ret.x86_64 = llir::X86_64Register::RBP; ret.mask = llir::Register::Mask::LowLowLow8;  ret.zero_others = false; break;
        case X86_REG_SIL:  ret.x86_64 = llir::X86_64Register::RSI; ret.mask = llir::Register::Mask::LowLowLow8;  ret.zero_others = false; break;
        case X86_REG_DIL:  ret.x86_64 = llir::X86_64Register::RDI; ret.mask = llir::Register::Mask::LowLowLow8;  ret.zero_others = false; break;
        case X86_REG_R8B:  ret.x86_64 = llir::X86_64Register::R8;  ret.mask = llir::Register::Mask::LowLowLow8;  ret.zero_others = false; break;
        case X86_REG_R9B:  ret.x86_64 = llir::X86_64Register::R9;  ret.mask = llir::Register::Mask::LowLowLow8;  ret.zero_others = false; break;
        case X86_REG_R10B: ret.x86_64 = llir::X86_64Register::R10; ret.mask = llir::Register::Mask::LowLowLow8;  ret.zero_others = false; break;
        case X86_REG_R11B: ret.x86_64 = llir::X86_64Register::R11; ret.mask = llir::Register::Mask::LowLowLow8;  ret.zero_others = false; break;
        case X86_REG_R12B: ret.x86_64 = llir::X86_64Register::R12; ret.mask = llir::Register::Mask::LowLowLow8;  ret.zero_others = false; break;
        case X86_REG_R13B: ret.x86_64 = llir::X86_64Register::R13; ret.mask = llir::Register::Mask::LowLowLow8;  ret.zero_others = false; break;
        case X86_REG_R14B: ret.x86_64 = llir::X86_64Register::R14; ret.mask = llir::Register::Mask::LowLowLow8;  ret.zero_others = false; break;
        case X86_REG_R15B: ret.x86_64 = llir::X86_64Register::R15; ret.mask = llir::Register::Mask::LowLowLow8;  ret.zero_others = false; break;

        // SSE registers
        case X86_REG_XMM0:  ret.x86_64 = llir::X86_64Register::XMM0;  ret.mask = llir::Register::Mask::Vector128Full; break;
        case X86_REG_XMM1:  ret.x86_64 = llir::X86_64Register::XMM1;  ret.mask = llir::Register::Mask::Vector128Full; break;
        case X86_REG_XMM2:  ret.x86_64 = llir::X86_64Register::XMM2;  ret.mask = llir::Register::Mask::Vector128Full; break;
        case X86_REG_XMM3:  ret.x86_64 = llir::X86_64Register::XMM3;  ret.mask = llir::Register::Mask::Vector128Full; break;
        case X86_REG_XMM4:  ret.x86_64 = llir::X86_64Register::XMM4;  ret.mask = llir::Register::Mask::Vector128Full; break;
        case X86_REG_XMM5:  ret.x86_64 = llir::X86_64Register::XMM5;  ret.mask = llir::Register::Mask::Vector128Full; break;
        case X86_REG_XMM6:  ret.x86_64 = llir::X86_64Register::XMM6;  ret.mask = llir::Register::Mask::Vector128Full; break;
        case X86_REG_XMM7:  ret.x86_64 = llir::X86_64Register::XMM7;  ret.mask = llir::Register::Mask::Vector128Full; break;
        case X86_REG_XMM8:  ret.x86_64 = llir::X86_64Register::XMM8;  ret.mask = llir::Register::Mask::Vector128Full; break;
        case X86_REG_XMM9:  ret.x86_64 = llir::X86_64Register::XMM9;  ret.mask = llir::Register::Mask::Vector128Full; break;
        case X86_REG_XMM10: ret.x86_64 = llir::X86_64Register::XMM10; ret.mask = llir::Register::Mask::Vector128Full; break;
        case X86_REG_XMM11: ret.x86_64 = llir::X86_64Register::XMM11; ret.mask = llir::Register::Mask::Vector128Full; break;
        case X86_REG_XMM12: ret.x86_64 = llir::X86_64Register::XMM12; ret.mask = llir::Register::Mask::Vector128Full; break;
        case X86_REG_XMM13: ret.x86_64 = llir::X86_64Register::XMM13; ret.mask = llir::Register::Mask::Vector128Full; break;
        case X86_REG_XMM14: ret.x86_64 = llir::X86_64Register::XMM14; ret.mask = llir::Register::Mask::Vector128Full; break;
        case X86_REG_XMM15: ret.x86_64 = llir::X86_64Register::XMM15; ret.mask = llir::Register::Mask::Vector128Full; break;

        // Segment registers
        case X86_REG_FS: ret.x86_64 = llir::X86_64Register::FS; ret.mask = llir::Register::Mask::Special; break;
        case X86_REG_GS: ret.x86_64 = llir::X86_64Register::GS; ret.mask = llir::Register::Mask::Special; break;
        case X86_REG_CS: ret.x86_64 = llir::X86_64Register::CS; ret.mask = llir::Register::Mask::Special; break;
        case X86_REG_SS: ret.x86_64 = llir::X86_64Register::SS; ret.mask = llir::Register::Mask::Special; break;
        case X86_REG_DS: ret.x86_64 = llir::X86_64Register::DS; ret.mask = llir::Register::Mask::Special; break;
        case X86_REG_ES: ret.x86_64 = llir::X86_64Register::ES; ret.mask = llir::Register::Mask::Special; break;

        default:
            pr_error("Unknown register!\n");
            assert(0);
    }

    return ret;
}
