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
    if (llinsn.src[0].type == llir::Operand::Type::IMM && llinsn.branch.target == llir::Branch::Target::RELATIVE) {
        // Annoyingly, capstone will automatically calculate the absolute address for immediate
        // relative jumps, so we have to subtract the instruction's address to undo this and
        // get the original relative offset.
        llinsn.src[0].imm -= llinsn.address;
    }
}

status_code llir_lifter_x86_64::lift(cs_insn *insn, std::vector<llir::Insn> &out) {
    cs_detail *detail = insn->detail;
    llir::Insn llinsn;

    memset(&llinsn, 0, sizeof(llinsn));
    llinsn.address = insn->address;

    switch (insn->id) {
        case X86_INS_JMP:
            assert(detail->groups_count > 0);

            llinsn.iclass = llir::Insn::Class::BRANCH;
            llinsn.branch.op = llir::Branch::Op::UNCONDITIONAL;
            llinsn.branch.target = contains_group(detail, X86_GRP_BRANCH_RELATIVE)
                                    ? llir::Branch::Target::RELATIVE
                                    : llir::Branch::Target::ABSOLUTE;
            llinsn.dest_cnt = 0;
            llinsn.src_cnt = 1;
            fill_operand(detail->x86.operands[0], llinsn.src[0]);
            relative_jump_fixup(llinsn);

            break;

        case X86_INS_JAE:   { TODO(); }
        case X86_INS_JA:    { TODO(); }
        case X86_INS_JBE:   { TODO(); }
        case X86_INS_JB:    { TODO(); }
        case X86_INS_JCXZ:  { TODO(); }
        case X86_INS_JECXZ: { TODO(); }
        case X86_INS_JE:    { llinsn.branch.op = llir::Branch::Op::EQ; goto jcc_common; }
        case X86_INS_JGE:   { TODO(); }
        case X86_INS_JG:    { TODO(); }
        case X86_INS_JLE:   { TODO(); }
        case X86_INS_JL:    { TODO(); }
        case X86_INS_JNE:   { llinsn.branch.op = llir::Branch::Op::NOT_EQ; goto jcc_common; }
        case X86_INS_JNO:   { TODO(); }
        case X86_INS_JNP:   { TODO(); /* does anybody even use PF?? */ }
        case X86_INS_JNS:   { llinsn.branch.op = llir::Branch::Op::NOT_NEGATIVE; goto jcc_common; }
        case X86_INS_JO:    { TODO(); }
        case X86_INS_JP:    { TODO(); /* does anybody even use PF?? */ }
        case X86_INS_JRCXZ: { TODO(); }
        case X86_INS_JS:    { llinsn.branch.op = llir::Branch::Op::NEGATIVE; goto jcc_common; }
        jcc_common:
            assert(detail->groups_count > 0);

            llinsn.iclass = llir::Insn::Class::BRANCH;
            llinsn.branch.target = contains_group(detail, X86_GRP_BRANCH_RELATIVE)
                                    ? llir::Branch::Target::RELATIVE
                                    : llir::Branch::Target::ABSOLUTE;
            llinsn.dest_cnt = 0;
            llinsn.src_cnt = 1;
            fill_operand(detail->x86.operands[0], llinsn.src[0]);
            relative_jump_fixup(llinsn);

            break;

        case X86_INS_CMP:
            assert(detail->x86.op_count == 2);
            llinsn.iclass = llir::Insn::Class::ALU;
            llinsn.alu.op = llir::Alu::Op::SUB;
            llinsn.dest_cnt = 0;
            llinsn.src_cnt = 2;
            llinsn.alu.modifies_flags = true;
            fill_operand(detail->x86.operands[0], llinsn.src[0]);
            fill_operand(detail->x86.operands[1], llinsn.src[1]);
            break;

        case X86_INS_MOVABS:
        case X86_INS_MOV:
            // MOV is pretty epic and can mean a lot of things. Determine what it's doing by looking at operand types
            if (detail->x86.operands[0].type == X86_OP_REG && detail->x86.operands[1].type == X86_OP_IMM) {
                // mov reg, imm - Load Immediate
                assert(detail->x86.op_count == 2);
                llinsn.iclass = llir::Insn::Class::ALU;
                llinsn.alu.op = llir::Alu::Op::LOAD_IMM;
                llinsn.dest_cnt = 1;
                llinsn.src_cnt = 1;
                fill_operand(detail->x86.operands[0], llinsn.dest[0]);
                fill_operand(detail->x86.operands[1], llinsn.src[0]);
            } else {
                log(LOGL_ERROR, "Unimplemented MOV type!\n");
                return status_code::UNIMPL_INSN;
            }
            break;

        case X86_INS_SYSCALL:
            llinsn.iclass = llir::Insn::Class::INTERRUPT;
            llinsn.interrupt.op = llir::Interrupt::Op::SYSCALL;
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

void llir_lifter_x86_64::fill_operand(cs_x86_op &op, llir::Operand &out) {
    switch (op.type) {
        case X86_OP_IMM:
            out.type = llir::Operand::Type::IMM;
            out.imm = op.imm;
            break;
        case X86_OP_MEM:
            out.type = llir::Operand::Type::MEM;
            out.memory.arch = Architecture::X86_64;
            out.memory.x86_64.segment = get_reg(op.mem.segment);
            out.memory.x86_64.base = get_reg(op.mem.base);
            out.memory.x86_64.index = get_reg(op.mem.index);
            out.memory.x86_64.scale = (uint8_t)op.mem.scale;
            out.memory.x86_64.disp = op.mem.disp;
            break;
        case X86_OP_REG:
            out.type = llir::Operand::Type::REG;
            out.reg = get_reg(op.reg);
            break;
        default:
            log(LOGL_ERROR, "Invalid operand type!\n");
            assert(0);
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
        case X86_REG_EAX: ret.x86_64 = llir::X86_64Register::RAX; ret.mask = llir::Register::Mask::Low32; break;
        case X86_REG_EBX: ret.x86_64 = llir::X86_64Register::RBX; ret.mask = llir::Register::Mask::Low32; break;
        case X86_REG_ECX: ret.x86_64 = llir::X86_64Register::RCX; ret.mask = llir::Register::Mask::Low32; break;
        case X86_REG_EDX: ret.x86_64 = llir::X86_64Register::RDX; ret.mask = llir::Register::Mask::Low32; break;
        case X86_REG_ESP: ret.x86_64 = llir::X86_64Register::RSP; ret.mask = llir::Register::Mask::Low32; break;
        case X86_REG_EBP: ret.x86_64 = llir::X86_64Register::RBP; ret.mask = llir::Register::Mask::Low32; break;
        case X86_REG_ESI: ret.x86_64 = llir::X86_64Register::RSI; ret.mask = llir::Register::Mask::Low32; break;
        case X86_REG_EDI: ret.x86_64 = llir::X86_64Register::RDI; ret.mask = llir::Register::Mask::Low32; break;

        // Segment Registers
        case X86_REG_FS: ret.x86_64 = llir::X86_64Register::FS; ret.mask = llir::Register::Mask::Special; break;
        case X86_REG_GS: ret.x86_64 = llir::X86_64Register::GS; ret.mask = llir::Register::Mask::Special; break;
        case X86_REG_CS: ret.x86_64 = llir::X86_64Register::CS; ret.mask = llir::Register::Mask::Special; break;
        case X86_REG_SS: ret.x86_64 = llir::X86_64Register::SS; ret.mask = llir::Register::Mask::Special; break;
        case X86_REG_DS: ret.x86_64 = llir::X86_64Register::DS; ret.mask = llir::Register::Mask::Special; break;
        case X86_REG_ES: ret.x86_64 = llir::X86_64Register::ES; ret.mask = llir::Register::Mask::Special; break;

        default:
            log(LOGL_ERROR, "Unknown register!\n");
            assert(0);
    }

    return ret;
}
