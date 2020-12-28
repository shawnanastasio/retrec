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
    llir::Extension extension = llir::Extension::NONE;

    switch (insn->id) {
        //
        // Branch
        //

        case X86_INS_JMP:
            assert(detail->groups_count > 0);

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
            llinsn.dest[0].memory().arch = Architecture::X86_64;
            llinsn.dest[0].memory().x86_64.base = get_reg(X86_REG_RSP);
            llinsn.dest[0].memory().x86_64.disp = -8;
            llinsn.dest[0].memory().x86_64.segment = get_reg(X86_REG_INVALID);
            llinsn.dest[0].memory().x86_64.index = get_reg(X86_REG_INVALID);
            llinsn.dest[0].memory().x86_64.scale = 1;
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
            llinsn.src[0].memory().arch = Architecture::X86_64;
            llinsn.src[0].memory().x86_64.base = get_reg(X86_REG_RSP);
            llinsn.src[0].memory().x86_64.disp = 8;
            llinsn.src[0].memory().x86_64.segment = get_reg(X86_REG_INVALID);
            llinsn.src[0].memory().x86_64.index = get_reg(X86_REG_INVALID);
            llinsn.src[0].memory().x86_64.scale = 1;
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
            assert(detail->groups_count > 0);

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
        case X86_INS_XOR:  llinsn.alu().op = llir::Alu::Op::XOR; llinsn.dest_cnt = 1; goto alu_bitwise_2op_common;
        alu_bitwise_2op_common:
            assert(detail->x86.op_count == 2);
            llinsn.src_cnt = 2;
            llinsn.alu().modifies_flags = true;
            llinsn.alu().flags_modified = llir::Alu::all_flags;
            llinsn.alu().flags_cleared = {{llir::Alu::Flag::CARRY, llir::Alu::Flag::OVERFLOW}, 2};
            fill_operand(detail->x86.operands[0], llinsn.src[0]);
            fill_operand(detail->x86.operands[1], llinsn.src[1]);
            if (llinsn.dest_cnt)
                fill_operand(detail->x86.operands[0], llinsn.dest[0]);

            break;

        case X86_INS_INC:
            assert(detail->x86.op_count == 1);
            llinsn.alu().op = llir::Alu::Op::ADD;
            llinsn.src_cnt = 2;
            llinsn.dest_cnt = 1;
            llinsn.alu().modifies_flags = true;

            using Flag = llir::Alu::Flag;
            llinsn.alu().flags_modified = {{Flag::OVERFLOW, Flag::SIGN, Flag::ZERO, Flag::AUXILIARY_CARRY, Flag::PARITY}, 5};

            fill_operand(detail->x86.operands[0], llinsn.dest[0]);
            fill_operand(detail->x86.operands[0], llinsn.src[0]);
            llinsn.src[1].imm() = 1;
            llinsn.src[1].width = llir::Operand::Width::_64BIT;
            break;

        case X86_INS_NOP:
            llinsn.alu().op = llir::Alu::Op::NOP;
            break;

        //
        // LoadStore
        //

        case X86_INS_MOVZX:   extension = llir::Extension::ZERO; goto mov_common;
        case X86_INS_MOVSX:   extension = llir::Extension::SIGN; goto mov_common;
        case X86_INS_MOVSXD:  extension = llir::Extension::SIGN; goto mov_common;
        case X86_INS_LEA:     goto mov_common;
        case X86_INS_MOVABS:  goto mov_common;
        case X86_INS_MOV:     goto mov_common;
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

        case X86_INS_PUSH:
            // Model PUSH as a STORE to RSP-8 + update
            llinsn.dest_cnt = 1;
            llinsn.src_cnt = 1;
            llinsn.loadstore().op = llir::LoadStore::Op::STORE;

            // Create an X86_64MemOp with base=(RSP), disp=(-8), update=PRE as the destination
            llinsn.dest[0].memory().arch = Architecture::X86_64;
            llinsn.dest[0].memory().x86_64.base = get_reg(X86_REG_RSP);
            llinsn.dest[0].memory().x86_64.disp = -8;
            llinsn.dest[0].memory().x86_64.segment = get_reg(X86_REG_INVALID);
            llinsn.dest[0].memory().x86_64.index = get_reg(X86_REG_INVALID);
            llinsn.dest[0].memory().x86_64.scale = 1;
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
            llinsn.src[0].memory().arch = Architecture::X86_64;
            llinsn.src[0].memory().x86_64.base = get_reg(X86_REG_RSP);
            llinsn.src[0].memory().x86_64.disp = 8;
            llinsn.src[0].memory().x86_64.segment = get_reg(X86_REG_INVALID);
            llinsn.src[0].memory().x86_64.index = get_reg(X86_REG_INVALID);
            llinsn.src[0].memory().x86_64.scale = 1;
            llinsn.src[0].memory().update = llir::MemOp::Update::POST;
            llinsn.src[0].width = llir::Operand::Width::_64BIT;

            // Fill the Destination with operand 0
            fill_operand(detail->x86.operands[0], llinsn.dest[0]);
            break;

        //
        // Interrupt
        //

        case X86_INS_SYSCALL:
            llinsn.interrupt().op = llir::Interrupt::Op::SYSCALL;
            llinsn.dest_cnt = 0;
            llinsn.src_cnt = 0;
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
            out.memory().arch = Architecture::X86_64;
            out.memory().x86_64.segment = get_reg(op.mem.segment);
            out.memory().x86_64.base = get_reg(op.mem.base);
            out.memory().x86_64.index = get_reg(op.mem.index);
            out.memory().x86_64.scale = (uint8_t)op.mem.scale;
            out.memory().x86_64.disp = op.mem.disp;
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
        case X86_REG_R10B: ret.x86_64 = llir::X86_64Register::R10; ret.mask = llir::Register::Mask::LowLowLow8;  ret.zero_others = false; break;
        case X86_REG_R11B: ret.x86_64 = llir::X86_64Register::R11; ret.mask = llir::Register::Mask::LowLowLow8;  ret.zero_others = false; break;
        case X86_REG_R12B: ret.x86_64 = llir::X86_64Register::R12; ret.mask = llir::Register::Mask::LowLowLow8;  ret.zero_others = false; break;
        case X86_REG_R13B: ret.x86_64 = llir::X86_64Register::R13; ret.mask = llir::Register::Mask::LowLowLow8;  ret.zero_others = false; break;
        case X86_REG_R14B: ret.x86_64 = llir::X86_64Register::R14; ret.mask = llir::Register::Mask::LowLowLow8;  ret.zero_others = false; break;
        case X86_REG_R15B: ret.x86_64 = llir::X86_64Register::R15; ret.mask = llir::Register::Mask::LowLowLow8;  ret.zero_others = false; break;

        // Segment Registers
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
