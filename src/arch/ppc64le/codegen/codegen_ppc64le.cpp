#include "llir.h"
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
    gen_context context(llir, code_buffer, assembler(code_buffer));
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

    log(LOGL_DEBUG, "Disassembling code buffer with capstone:\n");
    size_t expected_total = code_buffer.pos() / 4;
    size_t total_count = 0;
    while (total_count < expected_total) {
        cs_insn *cs_insns_tmp;
        size_t total_count_bytes = total_count * 4;
        size_t count = cs_disasm(cs_handle, (const uint8_t *)code + total_count_bytes,
                                 code_buffer.pos() - total_count_bytes, total_count_bytes, 0, &cs_insns_tmp);
        unique_cs_insn_arr cs_insns(cs_insns_tmp, cs_insn_deleter(count));

        cs_insn *cur;
        for (size_t i=0; i<count; i++) {
            cur = &cs_insns[i];
            log(LOGL_DEBUG, "0x%zx: %s %s\n", cur->address, cur->mnemonic, cur->op_str);
        }

        total_count += count;

        if (total_count != expected_total) {
            log(LOGL_DEBUG, "0x%zx: (unknown insn)\n", cur->address + 4);
            total_count++;
        }
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
                case llir::Branch::Op::CARRY:
                case llir::Branch::Op::NOT_CARRY:
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
                    if (target == ctx.local_branch_targets.end()) {
                        log(LOGL_ERROR, "Unable to resolve Immediate Branch to target 0x%lx\n", target);
                        return status_code::BADBRANCH;
                    }

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
void codegen_ppc64le<T>::llir$alu$helper$finalize_op(gen_context &ctx, const llir::Insn &insn, LastFlagOp op,
                                                      llir::Register::Mask mask) {
    assert(insn.alu.modifies_flags);


    if (insn.dest_cnt) {
        // Instruction has a destination register - copy it there
        //auto &reg_allocator = *ctx.reg_allocator(insn);
        //gpr_t dest = reg_allocator.get_fixed_gpr(insn.dest[0].reg);
        TODO();
    }

    if (!insn.alu.modifies_flags) {
        // Instruction doesn't modify flags, nothing left to do
        return;
    }

    // Record flag operation type in GPR_FIXED_FLAG_OP_TYPE
    uint32_t flag_data = build_flag_op_data(op, mask);
    macro$load_imm(ctx.assembler, GPR_FIXED_FLAG_OP_TYPE, flag_data, llir::Register::Mask::Low32, true);

    // Set lazy flag status according to operation type
    switch(op) {
        case LastFlagOp::SUB:
            // SUB needs carry+sign+parity+? to be lazily evaluated
            ctx.assembler.mcrf(CR_LAZYVALID, CR_ZEROS);
            break;

        default:
            TODO();
    }
}

template <typename T>
llir::Register::Mask codegen_ppc64le<T>::llir$alu$helper$determine_immediate_mask(const llir::Insn &insn) {
    assert(insn.src[0].type == llir::Operand::Type::REG);
    switch(insn.src[0].reg.mask) {
        case llir::Register::Mask::Full64:
        case llir::Register::Mask::Low32:
        case llir::Register::Mask::LowLow16:
        case llir::Register::Mask::LowLowLow8:
            return insn.src[0].reg.mask;
        case llir::Register::Mask::LowLowHigh8:
            return llir::Register::Mask::LowLowLow8;
        default:
            TODO();
    }
}

template <typename T>
void codegen_ppc64le<T>::llir$alu$load_imm(gen_context &ctx, const llir::Insn &insn) {
    log(LOGL_DEBUG, "alu$load_imm\n");
    assert(insn.dest_cnt == 1);
    assert(insn.dest[0].type == llir::Operand::Type::REG);
    assert(insn.src_cnt == 1);
    assert(insn.src[0].type == llir::Operand::Type::IMM);

    gpr_t rt = ctx.reg_allocator(insn)->get_fixed_gpr(insn.dest[0].reg);

    macro$load_imm(ctx.assembler, rt, insn.src[0].imm, insn.dest[0].reg.mask, insn.dest[0].reg.zero_others);
}

template <typename T>
void codegen_ppc64le<T>::llir$alu$sub(gen_context &ctx, const llir::Insn &insn) {
    log(LOGL_DEBUG, "alu$sub\n");
    assert(insn.src_cnt == 2);
    assert(insn.src[0].type == llir::Operand::Type::REG);

    auto &reg_allocator = *ctx.reg_allocator(insn);
    auto mask = llir$alu$helper$determine_immediate_mask(insn);

    // Ensure all operands are in registers
    macro$alu$load_operand_into_gpr(reg_allocator, ctx.assembler, insn.src[0], GPR_FIXED_FLAG_OP1, mask);
    macro$alu$load_operand_into_gpr(reg_allocator, ctx.assembler, insn.src[1], GPR_FIXED_FLAG_OP2, mask);

    if (insn.alu.modifies_flags)
        ctx.assembler.subo_(GPR_FIXED_FLAG_RES, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2);
    else
        ctx.assembler.subo(GPR_FIXED_FLAG_RES, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2);

    // Finalize operation
    llir$alu$helper$finalize_op(ctx, insn, LastFlagOp::SUB, mask);
}

/**
 * Return target virtual address for given branch
 */
template <typename T>
uint64_t codegen_ppc64le<T>::resolve_branch_target(const llir::Insn &insn) {
    uint64_t res;
    switch (insn.branch.target) {
        case llir::Branch::Target::RELATIVE:
            res = insn.address + (uint64_t)insn.src[0].imm;
            break;
        case llir::Branch::Target::ABSOLUTE:
            res = (uint64_t)insn.src[0].imm;
            break;
        default:
            TODO();
    }

    log(LOGL_DEBUG, "Resolved LLINSN branch target to 0x%lx: %s\n", res, llir::to_string(insn).c_str());
    return res;
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

template <typename T>
void codegen_ppc64le<T>::llir$branch$conditional(codegen_ppc64le::gen_context &ctx, const llir::Insn &insn) {
    log(LOGL_DEBUG, "branch$conditional\n");
    assert(insn.src_cnt == 1);

    uint64_t target = resolve_branch_target(insn);
    auto &reg_allocator = *ctx.reg_allocator(insn);

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

        case llir::Branch::Op::NEGATIVE:
            // blt
            bo = assembler::BO::FIELD_SET;
            cr_field = assembler::CR_LT;
            goto clean_map_common;

        case llir::Branch::Op::NOT_NEGATIVE:
            // bnlt
            bo = assembler::BO::FIELD_CLR;
            cr_field = assembler::CR_LT;
            goto clean_map_common;

        case llir::Branch::Op::POSITIVE:
            // bgt
            bo = assembler::BO::FIELD_SET;
            cr_field = assembler::CR_GT;
            goto clean_map_common;

        case llir::Branch::Op::CARRY:
            // lazily evaluated
            macro$branch$conditional$carry(ctx, reg_allocator, true, target);
            goto out;

        case llir::Branch::Op::NOT_CARRY:
            // lazily evaluated
            macro$branch$conditional$carry(ctx, reg_allocator, false, target);
            goto out;

        default:
            TODO();
    }


clean_map_common:
    // For operations that cleanly map to Power ISA flags, directly emit a cond branch relocation
    if (insn.src[0].type == llir::Operand::Type::IMM) {
        ctx.relocations.push_back({ ctx.code_buffer.pos(), 1, Relocation::BranchImmConditional{bo, cr_field, target} });
        ctx.assembler.nop();
    } else { TODO(); }

out:
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
    macro$load_imm(assembler, scratch, (uint16_t)runtime_context_ppc64le::NativeTarget::SYSCALL, llir::Register::Mask::Full64, true);
    assembler.std(scratch, 11, offsetof(runtime_context_ppc64le, native_function_call_target));

    // Load arch_leave_translated_code
    macro$load_imm(assembler, scratch, (int64_t)arch_leave_translated_code, llir::Register::Mask::Full64, true);
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
void codegen_ppc64le<T>::macro$load_imm(assembler &assembler, gpr_t dest, int64_t imm, llir::Register::Mask mask,
                                        bool zero_others) {
    // Negative numbers will always need to be masked if possible.
    bool need_mask = !zero_others && (imm < 0);

    // If we're not zero'ing others, mask out all but the target bits and use ori(s) instructions
    // to fill them in after.
    if (!zero_others)
        macro$mask_register(assembler, dest, dest, mask, true);

    // Special handling for LowLowHigh8. TODO: make this less ugly
    if (mask == llir::Register::Mask::LowLowHigh8) {
        assert(imm <= UINT8_MAX);
        assembler.ori(dest, dest, (uint16_t)(imm << 8));

        return;
    }

    if (imm <= INT16_MAX && imm >= INT16_MIN) {
        // If the immediate fits in an int16_t, we can just emit a single insn
        if (zero_others)
            assembler.addi(dest, 0, (int16_t)imm);
        else
            assembler.ori(dest, dest, (uint16_t)imm);

        if ((int)mask < (int)llir::Register::Mask::LowLow16)
            need_mask = true;
    } else if (imm <= INT32_MAX && imm >= INT32_MIN) {
        // If the immediate fits in an int32_t, emit addis and ori
        if (zero_others)
            assembler.addis(dest, 0, (int16_t)(imm >> 16));
        else
            assembler.oris(dest, dest, (uint16_t)(imm >> 16));

        if ((int16_t)imm)
            assembler.ori(dest, dest, (uint16_t)imm);

        if ((int)mask < (int)llir::Register::Mask::Low32)
            need_mask = true;
    } else {
        // Do the full song and dance for a 64-bit immediate load. Eventually we should use a TOC.

        if (zero_others)
            assembler.addis(dest, 0, (int16_t)(imm >> 48));
        else
            assembler.oris(dest, dest, (uint16_t)(imm >> 48));

        if ((int16_t)(imm >> 32))
            assembler.ori(dest, dest, (uint16_t)(imm >> 32));

        assembler.rldicr(dest, dest, 32, 31, false);

        if ((int16_t)(imm >> 16))
            assembler.oris(dest, dest, (int16_t)(imm >> 16));
        if ((int16_t)imm)
            assembler.ori(dest, dest, (int16_t)imm);
    }

    if (need_mask)
        macro$mask_register(assembler, dest, dest, mask, false);
}

template <typename T>
void codegen_ppc64le<T>::macro$alu$load_operand_into_gpr(typename T::RegisterAllocatorT &reg_allocator, assembler &assembler,
                                                         const llir::Operand &op, gpr_t target, llir::Register::Mask default_mask) {
    if (op.type == llir::Operand::Type::REG) {
        // Operand is in a register, move it to the appropriate FLAG_OP reg and mask it
        gpr_t gpr = reg_allocator.get_fixed_gpr(op.reg);

        if (op.reg.mask != llir::Register::Mask::LowLowHigh8) {
            // Directly load operand into FLAG_OP register with mask
            macro$mask_register(assembler, target, gpr, default_mask, false);
        } else {
            // Load operand into FLAG_OP register with mask and shift
            assembler.rldicl(target, gpr, 64-8, 63-8, false);
        }
    } else if (op.type == llir::Operand::Type::IMM) {
        // Operand is an immediate, load it into the appropriate FLAG_OP reg
        macro$load_imm(assembler, target, op.imm, default_mask, true);
    } else { TODO(); }
}

template <typename T>
void codegen_ppc64le<T>::macro$branch$unconditional(assembler &assembler, uint64_t my_address, uint64_t target, size_t insn_cnt) {
    int64_t diff = target - my_address;
    if (rel26_in_range(my_address, target)) {
        assert(insn_cnt >= 1); // Enough space for a single branch insn

        // Target is close enough to emit a relative branch
        assembler.b((int32_t)diff);
    } else if (target <= UINT26_MAX) {
        assert(insn_cnt >= 1);

        // Target is in the first 24-bits of the address space
        assembler.ba((int32_t)target);
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

        assembler.bc(bo, cr_field, (uint16_t)diff);
    } else { TODO(); }
}

template <typename T>
void codegen_ppc64le<T>::macro$branch$conditional$carry(gen_context &ctx, typename T::RegisterAllocatorT &allocator,
                                                        bool set, uint64_t target) {

    // This function emits a conditional branch depending on the state of the emulated CPU's Carry flag,
    // generating the Carry flag if necessary.
    //
    // 1. Determine whether the Carry flag has been calculated already by branching
    //    to the epilogue (5) if CR2[0] is set. Otherwise fall through.
    //
    // 2. Extract the low 8 bits from GPR_FIXED_FLAG_OP_TYPE to obtain branch table target.
    //    Add width to IP and branch.
    //
    // 3. The code at the destination will evaluate the Carry condition for the correct width.
    //    Refer to the table below for information on how the condition is evaluated for each
    //    width. The result is moved into CR1[2] and code branches to (4).
    //
    //    64 bit (doubleword, sub) - Use sube+subc to manually calculate carry
    //    64 bit (doubleword, add) - Use CA flag from XER
    //    32 bit (word)            - Use bit 32 from result
    //    16 bit (halfword)        - Use bit 16 from result
    //    8 bit  (byte)            - Use bit 8  from result
    //
    // 4. Set CR2[0] to indicate that the Carry flag has been evaluated.
    //
    // 5. Epilogue branches conditionally on CR1[2] to destination.

    // Skip to last instruction if Carry has already been evaluated
    ctx.assembler.bc(assembler::BO::FIELD_SET, CR_LAZYVALID_CARRY, 21 * 4);

    // Extract offset, add to NIA, branch
    ctx.assembler.rldicl(0, GPR_FIXED_FLAG_OP_TYPE, 0, 64-8, false); // Mask off all but the low 8 bits
    gpr_t scratch = allocator.allocate_gpr();
    ctx.assembler.lnia(scratch);
    ctx.assembler.add(0, 0, scratch);
    allocator.free_gpr(scratch);
    ctx.assembler.mtspr(assembler::SPR::CTR, 0);
    ctx.assembler.bctr();

    { // 8-bit - 3 insns
        constexpr uint32_t cr_carry_field_bit_position = 31 - CR_CARRY_FIELD_CARRY;
        // Extract carry bit from res[8] to r0[25]
        ctx.assembler.rldicl(0, GPR_FIXED_FLAG_RES, cr_carry_field_bit_position - 8, 0, false);
        ctx.assembler.mtocrf(1 << (7-CR_CARRY), 0);
        ctx.assembler.b(12 * 4);
    }

    { // 16-bit - 3 insns
        constexpr uint32_t cr_carry_field_bit_position = 31 - CR_CARRY_FIELD_CARRY;
        // Extract carry bit from res[16] to r0[25]
        ctx.assembler.rldicl(0, GPR_FIXED_FLAG_RES, cr_carry_field_bit_position - 16, 0, false);
        ctx.assembler.mtocrf(1 << (7-CR_CARRY), 0);
        ctx.assembler.b(9 * 4);
    }

    { // 32-bit - 3 insns
        constexpr uint32_t cr_carry_field_bit_position = 31 - CR_CARRY_FIELD_CARRY;
        // Extract carry bit from res[32] to r0[25]
        ctx.assembler.rldicl(0, GPR_FIXED_FLAG_RES, 64-(32 - cr_carry_field_bit_position), 0, true);
        ctx.assembler.mtocrf(1 << (7-CR_CARRY), 0);
        ctx.assembler.b(6 * 4);
    }

    { // 64-bit (ADD) - 2 insns
        ctx.assembler.mcrxrx(1 /* CR1 */);
        ctx.assembler.b(4 * 4);
    }

    { // 64-bit (SUB) - 3 insns
        ctx.assembler.subc(0, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_RES);
        ctx.assembler.sube(0, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP1);
        // r0 will now contain -1 on carry, or 0 otherwise.
        // Because of this, we can use mtocrf to set the contents of all bits in CR1 to 1/0 from r1.
        ctx.assembler.mtocrf(1 << (7-CR_CARRY), 0);
        /* fallthrough */
    }

    /* Set CR2[0] to indicate that the Carry flag is valid */
    ctx.assembler.crset(CR_LAZYVALID_CARRY);

    /* At this point, the Carry flag in CR1[2] is valid and we can branch on it */
    ctx.relocations.push_back({
            ctx.code_buffer.pos(),
            1,
            Relocation::BranchImmConditional{set ? assembler::BO::FIELD_SET : assembler::BO::FIELD_CLR, CR_CARRY_FIELD_CARRY, target}
    });
    ctx.assembler.nop();
}

template <typename T>
void codegen_ppc64le<T>::macro$mask_register(assembler &assembler, gpr_t dest, gpr_t src, llir::Register::Mask mask, bool invert) {
    if (invert) {
        // Mask out all requested bits
        switch(mask) {
            case llir::Register::Mask::Full64:
            case llir::Register::Mask::Low32:
                TODO();
            case llir::Register::Mask::LowLow16:
                assembler.rldicl(dest, src, 0, 63-16, false);
                break;
            case llir::Register::Mask::LowLowHigh8:
                assembler.rldicl(dest, src, 48, 8, false);
                assembler.rldicl(dest, src, 16, 0, false);
                break;
            case llir::Register::Mask::LowLowLow8:
                assembler.rldicl(dest, src, 0, 63-8, false);
                break;
            default:
                TODO();
        }
    } else {
        // Mask out all *except for* requested bits
        switch (mask) {
            case llir::Register::Mask::Full64:
                assembler.mr(dest, src); // Don't mask anything, just move
                break;
            case llir::Register::Mask::Low32:
                assembler.rldicl(dest, src, 0, 32, false);
                break;
            case llir::Register::Mask::LowLow16:
                assembler.rldicl(dest, src, 0, 48, false);
                break;
            case llir::Register::Mask::LowLowHigh8:
                TODO();
                //assembler.rldicl(reg, reg, 64-8, 56, false);
            case llir::Register::Mask::LowLowLow8:
                assembler.rldicl(dest, src, 0, 56, false);
                break;
            default:
                TODO();
        }
    }
}

// Explicitly instantiate for all supported traits
template class retrec::codegen_ppc64le<ppc64le::target_traits_x86_64>;
