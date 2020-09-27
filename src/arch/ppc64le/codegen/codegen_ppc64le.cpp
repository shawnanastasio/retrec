#include <arch/ppc64le/codegen/codegen_ppc64le.h>

#include <cstring>

using namespace retrec;
using namespace retrec::ppc64le;

// Offset of a host_translated_context member from runtime_context
#define TRANSLATED_CTX_OFF(member) (uint16_t)(offsetof(runtime_context_ppc64le, host_translated_context) + \
                                              offsetof(cpu_context_ppc64le, member))

template <typename T>
status_code codegen_ppc64le<T>::init() {
    // Allocate a branch table at an address that can fit in the "LI" field of I-form branch instructions
    /*
    uint64_t branch_table_vaddr = econtext.map().allocate_low_vaddr(0x10000);
    assert(branch_table_vaddr);
    assert(branch_table_vaddr <= 0b11111111111111111111111111); // I-form branches only have 26-bit wide immediates
    log(LOGL_INFO, "Allocated branch table at 0x%lx\n", branch_table_vaddr);
    branch_table = (uint32_t *)mmap((void *)branch_table_vaddr, 0x10000, PROT_READ | PROT_WRITE | PROT_EXEC,
                                    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (branch_table == (uint32_t *)-1) {
    }
    */

    return status_code::SUCCESS;
}

template <typename T>
status_code codegen_ppc64le<T>::translate(const lifted_llir_block& llir, std::optional<translated_code_region> &out) {

    log(LOGL_DEBUG, "vmx offset: %zu\n", offsetof(cpu_context_ppc64le, vmx));
    log(LOGL_DEBUG, "host_translated_context offset: %zu\n",
                    offsetof(runtime_context_ppc64le, host_translated_context));

    // Allocate an executable code buffer. For the initial size,
    // we'll use the number of llir instructions * 4 bytes (ppc64 insn size) * 2 (fudge).
    // As instructions are emitted, the buffer will be resized to the exact required size.
    size_t initial_code_size = llir.get_insns().size() * 4 * 2;
    void *code = econtext.get_code_allocator().allocate(initial_code_size);
    if (!code) {
        log(LOGL_ERROR, "Failed to allocate suitably sized code buffer!\n");
        return status_code::NOMEM;
    }
    simple_region_writer code_buffer(econtext.get_code_allocator(), code, initial_code_size);

    // First pass: emit instructions
    gen_context context = {llir, code_buffer, assembler(code_buffer), {}};
    for (const llir::Insn &insn : llir.get_insns()) {
        dispatch(context, insn);
    }

    // Shrink region to only use the minimum necessary space
    code_buffer.shrink();

    // Second pass: resolve relocations
    if (context.relocations.size()) {
        status_code ret = resolve_relocations(context);
        if (ret != status_code::SUCCESS) {
            log(LOGL_ERROR, "Failed to resolve relocations for generated code: %s!\n", status_code_str(ret));
            return ret;
        }
    }

    // Final pass (debug): Disassemble buffer with capstone and print out
    csh cs_handle;
    if (cs_open(CS_ARCH_PPC, (cs_mode)(CS_MODE_64 + CS_MODE_LITTLE_ENDIAN), &cs_handle) != CS_ERR_OK) {
        log(LOGL_ERROR, "Failed to open capstone handle for disassembly!\n");
        return status_code::NOMEM;
    }

    cs_insn *cs_insns_tmp;
    size_t count = cs_disasm(cs_handle, (const uint8_t *)code, code_buffer.pos(), 0, 0, &cs_insns_tmp);
    unique_cs_insn_arr cs_insns(cs_insns_tmp, cs_insn_deleter(count));

    log(LOGL_DEBUG, "Disassembling code buffer with capstone:\n");
    for (size_t i=0; i<count; i++) {
        cs_insn *cur = &cs_insns[i];
        log(LOGL_DEBUG, "0x%zx: %s %s\n", cur->address, cur->mnemonic, cur->op_str);
    }

    cs_close(&cs_handle);

    // Return translated code region
    out = {code, code_buffer.pos()};

    return status_code::SUCCESS;
}

template <typename T>
void codegen_ppc64le<T>::dispatch(gen_context &ctx, const llir::Insn &insn) {
    ctx.local_branch_targets.insert({ insn.address, ctx.code_buffer.pos_addr() });
    switch (insn.iclass) {
        case llir::Insn::Class::ALU:
            switch (insn.alu.op) {
                case llir::Alu::Op::LOAD_IMM:
                    llir$alu$load_imm(ctx, insn);
                    break;

                case llir::Alu::Op::SUB:
                    llir$alu$sub(ctx, insn);
                    break;

                default:
                    TODO();
            }
            break;
        case llir::Insn::Class::BRANCH:
            switch (insn.branch.op) {
                case llir::Branch::Op::UNCONDITIONAL:
                    llir$branch$unconditional(ctx, insn);
                    break;

                case llir::Branch::Op::EQ:
                case llir::Branch::Op::NOT_EQ:
                case llir::Branch::Op::NEGATIVE:
                case llir::Branch::Op::NOT_NEGATIVE:
                case llir::Branch::Op::POSITIVE:
                    llir$branch$conditional(ctx, insn);
                    break;

                default:
                    TODO();
            }
            break;
        case llir::Insn::Class::INTERRUPT:
            switch (insn.interrupt.op) {
                case llir::Interrupt::Op::SYSCALL:
                    llir$interrupt$syscall(ctx, insn);
                    break;

                default:
                    TODO();
            }
            break;
        default:
            TODO();
    }
}

template <typename T>
status_code codegen_ppc64le<T>::resolve_relocations(codegen_ppc64le<T>::gen_context &ctx) {
    for (auto &relocation : ctx.relocations) {
        auto res = std::visit(
            Overloaded {
                [&](const Relocation::BranchImmUnconditional &data) -> status_code {
                    auto target = ctx.local_branch_targets.find(data.abs_vaddr);
                    if (target == ctx.local_branch_targets.end())
                        return status_code::BADBRANCH;

                    {
                        uint64_t my_address = (uint64_t) ctx.code_buffer.start() + relocation.offset;
                        auto temp_assembler = ctx.assembler.create_temporary(relocation.offset);
                        macro$branch$unconditional(temp_assembler, my_address, target->second, relocation.insn_cnt);
                    }

                    return status_code::SUCCESS;
                },

                [&](const Relocation::BranchImmConditional &data) -> status_code {
                    auto target = ctx.local_branch_targets.find(data.abs_vaddr);
                    if (target == ctx.local_branch_targets.end())
                        return status_code::BADBRANCH;

                    {
                        uint64_t my_address = (uint64_t) ctx.code_buffer.start() + relocation.offset;
                        auto temp_assembler = ctx.assembler.create_temporary(relocation.offset);
                        macro$branch$conditional(temp_assembler, my_address, target->second, data.bo, data.cr_field,
                                                 relocation.insn_cnt);
                    }

                    return status_code::SUCCESS;
                }
            },
            relocation.data
        );

        if (res != status_code::SUCCESS)
            return res;
    }

    return status_code::SUCCESS;
}

//
// Codegen routines for all supported LLIR instructions
//

template <typename T>
void codegen_ppc64le<T>::llir$alu$load_imm(gen_context &ctx, const llir::Insn &insn) {
    log(LOGL_DEBUG, "alu$load_imm\n");
    assert(insn.dest_cnt == 1);
    assert(insn.dest[0].type == llir::Operand::Type::REG);
    assert(insn.src_cnt == 1);
    assert(insn.src[0].type == llir::Operand::Type::IMM);

    gpr_t rt = ctx.reg_allocator(insn)->get_fixed_gpr(insn.dest[0].reg);

    macro$load_imm(ctx.assembler, rt, insn.src[0].imm, insn.dest[0].reg.mask);
}

template<typename T>
void codegen_ppc64le<T>::llir$alu$sub(gen_context &ctx, const llir::Insn &insn) {
    log(LOGL_DEBUG, "alu$sub\n");
    assert(insn.src_cnt == 2);
    assert(insn.src[0].type == llir::Operand::Type::REG);

    auto mask = insn.src[0].reg.mask;
    auto &reg_allocator = *ctx.reg_allocator(insn);

    // Ensure all operands are in registers
    auto load_operand_into_gpr = [&](const auto &op, uint8_t op_count) {
        gpr_t target = op_count == 0 ? GPR_FIXED_FLAG_OP1 : GPR_FIXED_FLAG_OP2; // See JIT Flag ABI notes in codegen_ppc64le.h
        if (op.type == llir::Operand::Type::REG) {
            // Operand is in a register, move it to the appropriate FLAG_OP reg and mask it
            gpr_t gpr = reg_allocator.get_fixed_gpr(op.reg);
            ctx.assembler.mr(target, gpr);
            macro$mask_register(ctx.assembler, GPR_FIXED_FLAG_OP1, insn.src[0].reg.mask);

        } else if (op.type == llir::Operand::Type::IMM) {
            // Operand is an immediate, load it into the appropriate FLAG_OP reg
            macro$load_imm(ctx.assembler, target, op.imm, mask);

        } else { TODO(); }
    };
    load_operand_into_gpr(insn.src[0], 0);
    load_operand_into_gpr(insn.src[1], 1);
    gpr_t dest = insn.dest_cnt ? reg_allocator.get_fixed_gpr(insn.dest[0].reg) : 0 /* scratch */ ;

    if (insn.alu.modifies_flags)
        ctx.assembler.subo_(dest, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2);
    else
        ctx.assembler.subo(dest, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2);
}

/**
 * Return target virtual address for given branch
 */
template <typename T>
uint64_t codegen_ppc64le<T>::resolve_branch_target(const llir::Insn &insn) {
    switch (insn.branch.target) {
        case llir::Branch::Target::RELATIVE:
            return insn.address + insn.src[0].imm;
        case llir::Branch::Target::ABSOLUTE:
            return insn.src[0].imm;
        default:
            TODO();
    }
}

template <typename T>
void codegen_ppc64le<T>::llir$branch$unconditional(gen_context &ctx, const llir::Insn &insn) {
    log(LOGL_DEBUG, "branch$unconditional\n");
    assert(insn.dest_cnt == 0);
    assert(insn.src_cnt == 1);

    if (insn.src[0].type == llir::Operand::Type::IMM) {
        uint64_t target = resolve_branch_target(insn);

        // Experiment: always emit a relocation. This could make optimizations in later passes easier
        ctx.relocations.push_back({ ctx.code_buffer.pos(), 1, Relocation::BranchImmUnconditional{target} });
        ctx.assembler.nop();
    } else { TODO(); }

    // Invalidate the current register allocator after each indirect branch
    ctx.invalidate_reg_allocator(insn);
}

template<typename T>
void codegen_ppc64le<T>::llir$branch$conditional(codegen_ppc64le::gen_context &ctx, const llir::Insn &insn) {
    log(LOGL_DEBUG, "branch$conditional\n");
    assert(insn.src_cnt == 1);

    uint64_t target = resolve_branch_target(insn);

    assembler::BO bo;
    uint8_t cr_field;

    switch(insn.branch.op) {
        case llir::Branch::Op::EQ:
            // beq
            bo = assembler::BO::FIELD_SET;
            cr_field = assembler::CR_EQ;
            goto clean_map_common;

        case llir::Branch::Op::NOT_EQ:
            // bne
            bo = assembler::BO::FIELD_CLR;
            cr_field = assembler::CR_EQ;
            goto clean_map_common;

        case llir::Branch::Op::POSITIVE:
            // bgt
            bo = assembler::BO::FIELD_SET;
            cr_field = assembler::CR_GT;
            goto clean_map_common;

        case llir::Branch::Op::NOT_NEGATIVE:
            // bnlt
            bo = assembler::BO::FIELD_CLR;
            cr_field = assembler::CR_LT;
            goto clean_map_common;

        case llir::Branch::Op::NEGATIVE:
            // blt
            bo = assembler::BO::FIELD_SET;
            cr_field = assembler::CR_LT;
            goto clean_map_common;

        default:
            TODO();
    }


clean_map_common:
    // For operations that cleanly map to Power ISA flags, directly emit a cond branch relocation
    if (insn.src[0].type == llir::Operand::Type::IMM) {
        ctx.relocations.push_back({ ctx.code_buffer.pos(), 1, Relocation::BranchImmConditional{bo, cr_field, target} });
        ctx.assembler.nop();
    } else { TODO(); }

[[maybe_unused]] out:
    // Invalidate the current register allocator after each indirect branch
    ctx.invalidate_reg_allocator(insn);
}

template <typename T>
void codegen_ppc64le<T>::llir$interrupt$syscall(gen_context &ctx, const llir::Insn &insn) {
    log(LOGL_DEBUG, "interrupt$syscall\n");
    assert(insn.dest_cnt == 0 && insn.src_cnt == 0);
    ppc64le::assembler &assembler = ctx.assembler;

    // To handle a syscall, we have to re-enter native code, so emit a branch to arch_leave_translated_code.
    // Special considerations:
    // * arch_leave_translated code won't save LR for us, so we have to do it
    // * we need to store the callback in runtime_context(r11).host_native_context.native_function_call_target

    gpr_t scratch = ctx.reg_allocator(insn)->allocate_gpr();
    assert(scratch != GPR_INVALID);

    // Store address of callback
    macro$load_imm(assembler, scratch, (uint16_t)runtime_context_ppc64le::NativeTarget::SYSCALL, llir::Register::Mask::Full64);
    assembler.std(scratch, 11, offsetof(runtime_context_ppc64le, native_function_call_target));

    // Load arch_leave_translated_code
    macro$load_imm(assembler, scratch, (uint64_t)arch_leave_translated_code, llir::Register::Mask::Full64);
    assembler.mtspr(assembler::SPR::CTR, scratch);

    // Save LR
    assembler.mfspr(scratch, assembler::SPR::LR);
    assembler.std(scratch, 11, TRANSLATED_CTX_OFF(lr));

    // Branch
    assembler.bctrl();
}

//
// Macro assembler
//

template <typename T>
void codegen_ppc64le<T>::macro$load_imm(assembler &assembler, gpr_t dest, int64_t imm, llir::Register::Mask mask) {
    bool need_mask = false;

    if (imm <= INT16_MAX && imm >= INT16_MIN) {
        // If the immediate fits in an int16_t, we can just emit an addi
        assembler.addi(dest, 0, imm);

        if ((int)mask < (int)llir::Register::Mask::LowLow16)
            need_mask = true;
    } else if (imm <= INT32_MAX && imm >= INT32_MIN) {
        // If the immediate fits in an int32_t, emit addis and ori
        assembler.addis(dest, 0, (imm >> 16) & 0xFFFF);
        assembler.ori(dest, dest, imm & 0xFFFFU);

        if ((int)mask < (int)llir::Register::Mask::Low32)
            need_mask = true;
    } else {
        // Do the full song and dance for a 64-bit immediate load. Eventually we should use a TOC.
        assembler.addis(dest, 0, (imm >> 48) & 0xFFFF);
        assembler.ori(dest, dest, (imm >> 32) & 0xFFFF);
        assembler.rldicr(dest, dest, 32, 31, false);
        assembler.oris(dest, dest, (imm >> 16) & 0xFFFF);
        assembler.ori(dest, dest, imm & 0xFFFF);
        if (mask != llir::Register::Mask::Full64)
            need_mask = true;
    }

    if (need_mask)
        macro$mask_register(assembler, dest, mask);
}

template <typename T>
void codegen_ppc64le<T>::macro$branch$unconditional(assembler &assembler, uint64_t my_address, uint64_t target, size_t insn_cnt) {
    int64_t diff = target - my_address;
    if (rel26_in_range(my_address, target)) {
        assert(insn_cnt >= 1); // Enough space for a single branch insn

        // Target is close enough to emit a relative branch
        assembler.b(diff);
    } else if (target <= UINT26_MAX) {
        assert(insn_cnt >= 1);

        // Target is in the first 24-bits of the address space
        assembler.ba(target);
    } else {
        // Far branch. TODO.
        TODO();
    }
}

template <typename T>
void codegen_ppc64le<T>::macro$branch$conditional(assembler &assembler, uint64_t my_address, uint64_t target,
                                                  assembler::BO bo, uint8_t cr_field, size_t insn_cnt) {
    int64_t diff = target - my_address;
    if (rel16_in_range(my_address, target)) {
        assert(insn_cnt >= 1); // Enough space for a single branch insn

        assembler.bc(bo, cr_field, diff);
    } else { TODO(); }
}

template <typename T>
void codegen_ppc64le<T>::macro$mask_register(ppc64le::assembler &assembler, ppc64le::gpr_t reg, llir::Register::Mask mask) {
    switch(mask) {
        case llir::Register::Mask::Full64:
            break;
        case llir::Register::Mask::Low32:
            assembler.rldicl(reg, reg, 0, 32, false);
            break;
        case llir::Register::Mask::LowLow16:
            assembler.rldicl(reg, reg, 0, 48, false);
            break;
        case llir::Register::Mask::LowLowHigh8:
            TODO();
        case llir::Register::Mask::LowLowLow8:
            TODO();
            break;
        default:
            TODO();
    }
}

// Explicitly instantiate for all supported traits
template class retrec::codegen_ppc64le<ppc64le::target_traits_x86_64>;
