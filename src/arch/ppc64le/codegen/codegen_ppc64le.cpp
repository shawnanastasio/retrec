#include <llir.h>
#include <arch/ppc64le/codegen/codegen_ppc64le.h>
#include <arch/ppc64le/codegen/codegen_types.h>
#include <arch/ppc64le/codegen/assembler.h>

#include <type_traits>
#include <variant>
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
    pr_info("Allocated branch table at 0x%lx\n", branch_table_vaddr);
    branch_table = (uint32_t *)mmap((void *)branch_table_vaddr, 0x10000, PROT_READ | PROT_WRITE | PROT_EXEC,
                                    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (branch_table == (uint32_t *)-1) {
    }
    */

    return status_code::SUCCESS;
}

template <typename T>
codegen_ppc64le<T>::gen_context::gen_context(const lifted_llir_block &llir_)
        : llir(llir_) {
    assembler = std::make_unique<ppc64le::assembler>();
    stream = std::make_unique<ppc64le::instruction_stream>(*assembler);
    assembler->set_stream(&*stream);
}

template <typename T>
status_code codegen_ppc64le<T>::translate(const lifted_llir_block& llir, std::optional<translated_code_region> &out) {

    pr_debug("vmx offset: %zu\n", offsetof(cpu_context_ppc64le, vmx));
    pr_debug("host_translated_context offset: %zu\n",
                    offsetof(runtime_context_ppc64le, host_translated_context));

    // First pass: dispatch and translate all LLIR instructions
    gen_context context(llir);
    for (const llir::Insn &insn : llir.get_insns()) {
        dispatch(context, insn);
    }

    // Second pass: resolve relocations
    status_code res = resolve_relocations(context);
    if (res != status_code::SUCCESS) {
        pr_error("Failed to resolve relocations for generated code: %s!\n", status_code_str(res));
        return res;
    }

    // Third pass: Emit all generated instructions to a code buffer
    size_t code_size = context.stream->code_size();
    void *code = econtext.get_code_allocator().allocate(code_size);
    if (!code) {
        pr_error("Failed to allocate suitably sized code buffer!\n");
        return status_code::NOMEM;
    }

    res = context.stream->emit_all_to_buf((uint8_t *)code, code_size);
    if (res != status_code::SUCCESS) {
        pr_error("Failed to emit instructions to code buffer: %s!\n", status_code_str(res));
        return res;
    }

    // Return translated code region
    out = {code, code_size};

    return status_code::SUCCESS;
}

template <typename T>
void codegen_ppc64le<T>::dispatch(gen_context &ctx, const llir::Insn &insn) {
    ctx.local_branch_targets.insert({ insn.address, ctx.stream->size() });
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
                case llir::Branch::Op::OVERFLOW:
                case llir::Branch::Op::NOT_OVERFLOW:
                case llir::Branch::Op::X86_ABOVE:
                case llir::Branch::Op::X86_BELOW_EQ:
                case llir::Branch::Op::X86_GREATER_EQ:
                case llir::Branch::Op::X86_LESS:
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
    // Walk the instruction stream and look for relocationsa
    for (size_t i = 0; i < ctx.stream->size(); i++) {
        auto &insn = (*ctx.stream)[i];

        if (!insn.aux)
            continue;
        instruction_aux &aux = *insn.aux;

        if (!aux.relocation)
            continue;
        relocation &relocation = *aux.relocation;

        auto res = std::visit(
            Overloaded {
                [&](const relocation::imm_rel_vaddr_fixup &data) -> status_code {
                    /**
                     * imm_rel_vaddr_fixup - Modify the instruction's immediate field to point to
                     * the relative address corresponding to the provided absolute target virtual address.
                     */
                    auto target_index_it = ctx.local_branch_targets.find(data.abs_vaddr);
                    if (target_index_it == ctx.local_branch_targets.end()) {
                        pr_error("Unable to resolve Immediate Branch to target 0x%lx\n", target);
                        return status_code::BADBRANCH;
                    }
                    size_t target_index = target_index_it->second;

                    // Calculate the target's relative offset from us
                    int64_t target_off = target_index*INSN_SIZE - i*INSN_SIZE;

                    // Helper to fix up absolute branches
                    auto fixup_absolute_branch = [](bool &aa) {
                        if (aa) {
                            pr_warn("Relocation requires changing branch from absolute to relative\n");
                            aa = false;
                        }
                    };

                    // Disable compiler diagnostics for implicit conversions for this block.
                    ALLOW_IMPLICIT_INT_CONVERSION();

                    // Update relative address
                    switch (insn.operation()) {
                        case Operation::B:
                        {
                            // B can do 26-bit relative branches
                            if (target_off < INT26_MIN || target_off > INT26_MAX)
                                return status_code::BADBRANCH;

                            insn_arg<0 /* target */, Operation::B>(insn) = target_off;
                            fixup_absolute_branch(insn_arg<1 /* aa */, Operation::B>(insn));

                            break;
                        }

                        case Operation::BC:
                        {
                            // BC can do 16-bit relative branches
                            if (target_off < INT16_MIN || target_off > INT16_MAX)
                                return status_code::BADBRANCH;

                            insn_arg<2 /* target */, Operation::BC>(insn) = target_off;
                            fixup_absolute_branch(insn_arg<3 /* aa */, Operation::BC>(insn));

                            break;
                        }

                        default:
                            return status_code::UNIMPL_INSN;
                    }

                    DISALLOW_IMPLICIT_INT_CONVERSION();

                    return status_code::SUCCESS;
                },
            },
            relocation.data
        );

        // Bail out if a relocation failed
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
    if (insn.dest_cnt) {
        // Instruction has a destination register - copy it there
        assert(insn.dest[0].type == llir::Operand::Type::REG);

        gpr_t dest = ctx.reg_allocator().get_fixed_gpr(insn.dest[0].reg);
        macro$move_register_masked(*ctx.assembler, dest, GPR_FIXED_FLAG_RES, mask,
                                   insn.dest[0].reg.mask, insn.dest[0].reg.zero_others, false);
    }

    if (insn.alu.modifies_flags && mask != llir::Register::Mask::Full64) {
        // If the instruction modifies flags and the mask is < 64, we need to generate the cr0 flags
        switch (mask) {
            case llir::Register::Mask::Low32:
                // For 32-bit, do a signed compare to immediate 0
                ctx.assembler->cmpwi(0 /* cr0 */, GPR_FIXED_FLAG_RES, 0);
                break;

            case llir::Register::Mask::LowLow16:
                // For 16-bit, do a sign extension with Rc=1
                ctx.assembler->extsh(0, GPR_FIXED_FLAG_RES, true);
                break;

            case llir::Register::Mask::LowLowLow8:
                // For 8-bit, do a sign extension with Rc=1
                ctx.assembler->extsb(0, GPR_FIXED_FLAG_RES, true);
                break;

            default:
                TODO();
        }
    }


    if (!insn.alu.modifies_flags) {
        // Instruction doesn't modify flags, nothing left to do
        return;
    }

    // Record flag operation type in GPR_FIXED_FLAG_OP_TYPE
    uint32_t flag_data = build_flag_op_data(op, mask);
    macro$load_imm(*ctx.assembler, GPR_FIXED_FLAG_OP_TYPE, flag_data, llir::Register::Mask::Low32, true);

    // Set lazy flag status according to operation type
    switch (op) {
        case LastFlagOp::SUB:
            // SUB needs carry+sign+parity+? to be lazily evaluated
            ctx.assembler->mcrf(CR_LAZYVALID, CR_ZEROS);
            break;

        default:
            TODO();
    }
}

template <typename T>
llir::Register::Mask codegen_ppc64le<T>::llir$alu$helper$determine_immediate_mask(const llir::Insn &insn) {
    assert(insn.src[0].type == llir::Operand::Type::REG);
    switch (insn.src[0].reg.mask) {
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
void codegen_ppc64le<T>::llir$alu$helper$load_operand_into_gpr(gen_context &ctx, const llir::Insn &insn, const llir::Operand &op,
                                                              gpr_t target, llir::Register::Mask default_mask) {
    (void)insn;
    if (op.type == llir::Operand::Type::REG) {
        // Operand is in a register, move it to the appropriate FLAG_OP reg and mask it
        gpr_t gpr = ctx.reg_allocator().get_fixed_gpr(op.reg);

        if (op.reg.mask != llir::Register::Mask::LowLowHigh8) {
            // Directly load operand into FLAG_OP register with mask
            macro$mask_register(*ctx.assembler, target, gpr, default_mask, false, false);
        } else {
            // Load operand into FLAG_OP register with mask and shift
            ctx.assembler->rldicl(target, gpr, 64-8, 64-8, false);
        }
    } else if (op.type == llir::Operand::Type::IMM) {
        // Operand is an immediate, load it into the appropriate FLAG_OP reg
        macro$load_imm(*ctx.assembler, target, op.imm, default_mask, true);
    } else { TODO(); }
}


template <typename T>
void codegen_ppc64le<T>::llir$alu$load_imm(gen_context &ctx, const llir::Insn &insn) {
    pr_debug("alu$load_imm\n");
    assert(insn.dest_cnt == 1);
    assert(insn.dest[0].type == llir::Operand::Type::REG);
    assert(insn.src_cnt == 1);
    assert(insn.src[0].type == llir::Operand::Type::IMM);

    gpr_t rt = ctx.reg_allocator().get_fixed_gpr(insn.dest[0].reg);

    macro$load_imm(*ctx.assembler, rt, insn.src[0].imm, insn.dest[0].reg.mask, insn.dest[0].reg.zero_others);
}

template <typename T>
void codegen_ppc64le<T>::llir$alu$sub(gen_context &ctx, const llir::Insn &insn) {
    pr_debug("alu$sub\n");
    assert(insn.src_cnt == 2);
    assert(insn.src[0].type == llir::Operand::Type::REG);

    auto mask = llir$alu$helper$determine_immediate_mask(insn);

    // Ensure all operands are in registers
    llir$alu$helper$load_operand_into_gpr(ctx, insn, insn.src[0], GPR_FIXED_FLAG_OP1, mask);
    llir$alu$helper$load_operand_into_gpr(ctx, insn, insn.src[1], GPR_FIXED_FLAG_OP2, mask);

    if (insn.alu.modifies_flags && mask == llir::Register::Mask::Full64)
        ctx.assembler->sub_(GPR_FIXED_FLAG_RES, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2);
    else
        ctx.assembler->sub(GPR_FIXED_FLAG_RES, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2);

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

    pr_debug("Resolved LLINSN branch target to 0x%lx: %s\n", res, llir::to_string(insn).c_str());
    return res;
}

template <typename T>
void codegen_ppc64le<T>::llir$branch$unconditional(gen_context &ctx, const llir::Insn &insn) {
    pr_debug("branch$unconditional\n");
    assert(insn.dest_cnt == 0);
    assert(insn.src_cnt == 1);

    if (insn.src[0].type == llir::Operand::Type::IMM) {
        uint64_t target = resolve_branch_target(insn);

        // Always emit a relocation. This could make optimizations in later passes easier.
        ctx.assembler->b(0);
        ctx.stream->add_aux(true, relocation{1, relocation::imm_rel_vaddr_fixup{target}});
    } else { TODO(); }
}

template <typename T>
void codegen_ppc64le<T>::llir$branch$conditional(codegen_ppc64le::gen_context &ctx, const llir::Insn &insn) {
    pr_debug("branch$conditional\n");
    assert(insn.src_cnt == 1);

    uint64_t target = resolve_branch_target(insn);
    uint8_t cr_field;
    BO bo;

    switch (insn.branch.op) {
        case llir::Branch::Op::EQ:
            // beq
            bo = BO::FIELD_SET;
            cr_field = assembler::CR_EQ;
            break;

        case llir::Branch::Op::NOT_EQ:
            // bne
            bo = BO::FIELD_CLR;
            cr_field = assembler::CR_EQ;
            break;

        case llir::Branch::Op::NEGATIVE:
            // blt
            bo = BO::FIELD_SET;
            cr_field = assembler::CR_LT;
            break;

        case llir::Branch::Op::NOT_NEGATIVE:
            // bnlt
            bo = BO::FIELD_CLR;
            cr_field = assembler::CR_LT;
            break;

        case llir::Branch::Op::POSITIVE:
            // bgt
            bo = BO::FIELD_SET;
            cr_field = assembler::CR_GT;
            break;

        case llir::Branch::Op::CARRY:
            // lazily evaluated
            macro$branch$conditional$carry(ctx);
            bo = BO::FIELD_SET;
            cr_field = CR_LAZY_FIELD_CARRY;
            break;

        case llir::Branch::Op::NOT_CARRY:
            // lazily evaluated
            macro$branch$conditional$carry(ctx);
            bo = BO::FIELD_CLR;
            cr_field = CR_LAZY_FIELD_CARRY;
            break;

        case llir::Branch::Op::OVERFLOW:
            // lazily evaluated
            macro$branch$conditional$overflow(ctx);
            bo = BO::FIELD_SET;
            cr_field = CR_LAZY_FIELD_OVERFLOW;
            break;

        case llir::Branch::Op::NOT_OVERFLOW:
            // lazily evaluated
            macro$branch$conditional$overflow(ctx);
            bo = BO::FIELD_CLR;
            cr_field = CR_LAZY_FIELD_OVERFLOW;
            break;

        case llir::Branch::Op::X86_BELOW_EQ: bo = BO::FIELD_CLR; goto above_common;
        case llir::Branch::Op::X86_ABOVE: bo = BO::FIELD_SET; goto above_common;
        above_common:
            // Relies on a combination of flags, one of which is lazily evaluated (CF)
            macro$branch$conditional$carry(ctx);

            // !CR && !ZF can be implemented with CRNOR
            ctx.assembler->crnor(CR_SCRATCH*4+0, CR_LAZY_FIELD_CARRY, 0*4+assembler::CR_EQ);
            cr_field = CR_SCRATCH*4+0;

            break;

        case llir::Branch::Op::X86_LESS: bo = BO::FIELD_CLR; goto greater_eq_common;
        case llir::Branch::Op::X86_GREATER_EQ: bo = BO::FIELD_SET; goto greater_eq_common;
        greater_eq_common:
            // Relies on a combination of flags, one of which is lazily evaluated (OF)
            macro$branch$conditional$overflow(ctx);

            // SF == OF can be implemented with CREQV
            ctx.assembler->creqv(CR_SCRATCH*4+0, CR_LAZY_FIELD_OVERFLOW, 0*4+assembler::CR_LT);
            cr_field = CR_SCRATCH*4+0;

            break;

        default:
            TODO();
    }

    // With the condition determined, emit a relocation for a conditional branch
    if (insn.src[0].type == llir::Operand::Type::IMM) {
        ctx.assembler->bc(bo, cr_field, 0);
        ctx.stream->add_aux(true, relocation{1, relocation::imm_rel_vaddr_fixup{target}});
    } else { TODO(); }
}

template <typename T>
void codegen_ppc64le<T>::llir$interrupt$syscall(gen_context &ctx, const llir::Insn &insn) {
    pr_debug("interrupt$syscall\n");
    assert(insn.dest_cnt == 0 && insn.src_cnt == 0);

    // To handle a syscall, we have to re-enter native code, so emit a branch to arch_leave_translated_code.
    // Special considerations:
    // * arch_leave_translated code won't save LR for us, so we have to do it
    // * we need to store the callback in runtime_context(r11).host_native_context.native_function_call_target

    gpr_t scratch = ctx.reg_allocator().allocate_gpr();

    // Store address of callback
    macro$load_imm(*ctx.assembler, scratch, (uint16_t)runtime_context_ppc64le::NativeTarget::SYSCALL, llir::Register::Mask::Full64, true);
    ctx.assembler->std(scratch, 11, offsetof(runtime_context_ppc64le, native_function_call_target));

    // Load arch_leave_translated_code
    macro$load_imm(*ctx.assembler, scratch, (int64_t)arch_leave_translated_code, llir::Register::Mask::Full64, true);
    ctx.assembler->mtspr(SPR::CTR, scratch);

    // Save LR
    ctx.assembler->mfspr(scratch, SPR::LR);
    ctx.assembler->std(scratch, 11, TRANSLATED_CTX_OFF(lr));

    // Branch
    ctx.assembler->bctrl();

    ctx.reg_allocator().free_gpr(scratch);
}

//
// Macro assembler
//

/**
 * Small helper to determine if a given int64_t immediate can be losslessly converted
 * into integral type `T`.
 */
template <typename T>
bool imm_fits_in(int64_t imm) {
    return (T)imm == imm;
}

template <typename T>
void codegen_ppc64le<T>::macro$load_imm(assembler &assembler, gpr_t dest, int64_t imm, llir::Register::Mask mask,
                                        bool zero_others) {
    auto ori = [&](auto a, uint16_t b) { if (b) assembler.ori(a, a, b); };
    auto oris = [&](auto a, uint16_t b) { if (b) assembler.oris(a, a, b); };

    if (!zero_others)
        macro$mask_register(assembler, dest, dest, mask, true, false);

    if (mask == llir::Register::Mask::LowLowLow8) {
        if (!zero_others)
            ori(dest, (uint16_t)(imm & 0xFF));
        else
            assembler.addi(dest, 0, (int16_t)(imm & 0xFF));
    } else if (mask == llir::Register::Mask::LowLowHigh8) {
        uint16_t i = (uint16_t)((imm << 8) & 0xFF00U);
        if (!zero_others)
            ori(dest, i);
        else {
            assembler.addi(dest, 0, i);
            if (i & (1 << 15))
                // If i has MSBit set, mask out top 48 bits to remove sign extension.
                assembler.rldicl(dest, dest, 0, 64-16, false);
        }
    } else if (mask == llir::Register::Mask::LowLow16) {
        uint16_t i = (uint16_t)imm;
        if (!zero_others)
            ori(dest, i);
        else {
            assembler.addi(dest, 0, i);
            if (i & (1 << 15))
                // If i has MSBit set, mask out top 48 bits to remove sign extension.
                assembler.rldicl(dest, dest, 0, 64-16, false);
        }
    } else if (mask == llir::Register::Mask::Low32) {
        uint32_t i = (uint32_t)imm;
        if (!zero_others) {
            oris(dest, (uint16_t)(i >> 16));
            ori(dest, (uint16_t)i);
        } else {
            if (imm < 0) {
                if (imm_fits_in<int16_t>(imm))
                    assembler.addi(dest, 0, (int16_t)imm);
                else {
                    assembler.addis(dest, 0, (int16_t)(i >> 16));
                    ori(dest, (uint16_t)i);
                }
            } else {
                if (imm_fits_in<uint16_t>(imm) && !(imm & (1 << 15)))
                    assembler.addi(dest, 0, (int16_t)imm);
                else {
                    assembler.addis(dest, 0, (int16_t)(i >> 16));
                    ori(dest, (uint16_t)i);
                }
            }

            if (i & (1 << 31)) {
                // If i has MSBit set, mask out top 32 bits to remove sign extension.
                assembler.rldicl(dest, dest, 0, 64-32, false);
            }
        }
    } else /* llir::Register::Mask::Full64 */ {
        assert(zero_others); // Can't perform a 64-bit load without touching all 64-bits in the register
        if (imm < 0) {
            // For negative numbers we can take advantage of sign extension
            if (imm_fits_in<int16_t>(imm)) {
                assembler.addi(dest, 0, (int16_t)imm);
            } else if (imm_fits_in<int32_t>(imm)) {
                assembler.addis(dest, 0, (int16_t)(imm >> 16));
                ori(dest, (uint16_t)imm);
            } else {
                assembler.addis(dest, 0, (int16_t)(imm >> 48));
                ori(dest, (uint16_t)(imm >> 32));
                assembler.rldicr(dest, dest, 32, 31, false);
                oris(dest, (uint16_t)(imm >> 16));
                ori(dest, (uint16_t)imm);
            }
        } else {
            // For positive numbers, we have to take care to avoid sign extension
            if (imm_fits_in<uint16_t>(imm)) {
                assembler.addi(dest, 0, (int16_t)imm);
                if (imm & (1 << 15))
                    // If imm has MSBit set, mask out top 48 bits to remove sign extension.
                    assembler.rldicl(dest, dest, 0, 64-16, false);
            } else if (imm_fits_in<uint32_t>(imm)) {
                assembler.addis(dest, 0, (int16_t)(imm >> 16));
                ori(dest, (uint16_t)imm);
                if (imm & (1 << 31))
                    // If imm has MSBit set, mask out top 32 bits to remove sign extension.
                    assembler.rldicl(dest, dest, 0, 64-32, false);
            } else {
                assembler.addis(dest, 0, (int16_t)(imm >> 48));
                ori(dest, (uint16_t)(imm >> 32));
                assembler.rldicr(dest, dest, 32, 31, false);
                oris(dest, (uint16_t)(imm >> 16));
                ori(dest, (uint16_t)imm);
            }
        }
    }
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
                                                  BO bo, uint8_t cr_field, size_t insn_cnt) {
    int64_t diff = target - my_address;
    if (rel16_in_range(my_address, target)) {
        assert(insn_cnt >= 1); // Enough space for a single branch insn

        assembler.bc(bo, cr_field, (uint16_t)diff);
    } else { TODO(); }
}

template <typename T>
void codegen_ppc64le<T>::macro$branch$conditional$carry(gen_context &ctx) {

    // This function emits a conditional branch depending on the state of the emulated CPU's Carry flag,
    // generating the Carry flag if necessary.
    //
    // 1. Determine whether the Carry flag has been calculated already by branching
    //    to the epilogue (5) if CR_LAZYVALID_CARRY is set. Otherwise fall through.
    //
    // 2. Extract the low 8 bits from GPR_FIXED_FLAG_OP_TYPE to obtain branch table target.
    //    Add width to IP and branch.
    //
    // 3. The code at the destination will evaluate the Carry condition for the correct width.
    //    Refer to the table below for information on how the condition is evaluated for each
    //    width. Rc=1 instructions are used to store the compliment of the carry flag in cr0[eq].
    //
    //    64 bit (doubleword, sub) - Use sube+subc to manually calculate carry
    //    64 bit (doubleword, add) - Use CA flag from XER
    //    32 bit (word)            - Use bit 32 from result
    //    16 bit (halfword)        - Use bit 16 from result
    //    8 bit  (byte)            - Use bit 8  from result
    //
    //    Width-specific code then jumps to common code that moves ~cr0[eq] into CR_LAZY_FIELD_CARRY.
    //
    // 4. Set CR2[0] to indicate that the Carry flag has been evaluated.
    //
    // 5. Carry is now valid and can be branched on conditionally

    // Skip to last instruction if CF has already been evaluated
    ctx.assembler->bc(BO::FIELD_SET, CR_LAZYVALID_CARRY, 21 * 4);

    // Preserve cr0 in CR_SCRATCH
    ctx.assembler->mcrf(CR_SCRATCH, 0);

    // Extract offset, add to NIA, branch
    ctx.assembler->rldicl(0, GPR_FIXED_FLAG_OP_TYPE, 0, 64-8, false); // Mask off all but the low 8 bits
    gpr_t scratch = ctx.reg_allocator().allocate_gpr();
    ctx.assembler->lnia(scratch);
    ctx.assembler->add(0, 0, scratch);
    ctx.reg_allocator().free_gpr(scratch);
    ctx.assembler->mtspr(SPR::CTR, 0);
    ctx.assembler->bctr();

    { // 8-bit - 2 insns
        // Extract carry bit from res[8]. This sets cr0[gt] to the inverse of the carry bit.
        ctx.assembler->rldicl(0, GPR_FIXED_FLAG_RES, 64 - 8, 63, true);
        ctx.assembler->b(10 * 4);
    }

    { // 16-bit - 2 insns
        // Extract carry bit from res[16]. This sets cr0[gt] to the inverse of the carry bit.
        ctx.assembler->rldicl(0, GPR_FIXED_FLAG_RES, 64 - 16, 63, true);
        ctx.assembler->b(8 * 4);
    }

    { // 32-bit - 2 insns
        // Extract carry bit from res[32]. This sets cr0[gt] to the inverse of the carry bit.
        ctx.assembler->rldicl(0, GPR_FIXED_FLAG_RES, 64 - 32, 63, true);
        ctx.assembler->b(6 * 4);
    }

    { // 64-bit (ADD) - 3 insns
        // Calculate carry bit and set cr0[eq] accordingly.
        ctx.assembler->subc(0, GPR_FIXED_FLAG_RES, GPR_FIXED_FLAG_OP1);
        ctx.assembler->sube_(0, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP1);
        ctx.assembler->b(3 * 4);
    }

    { // 64-bit (SUB) - 2 insns
        // Calculate carry bit and set cr0[eq] accordingly.
        ctx.assembler->subc(0, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_RES);
        ctx.assembler->sube_(0, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP1);
        /* fallthrough */
    }

    // Move !cr0[eq] to CR_LAZY[CARRY]
    ctx.assembler->crnot(CR_LAZY_FIELD_CARRY, 4*0 + assembler::CR_EQ);

    // Set CR_LAZYVALID_CARRY to indicate that the Carry flag is valid
    ctx.assembler->crset(CR_LAZYVALID_CARRY);

    // Restore cr0
    ctx.assembler->mcrf(0, CR_SCRATCH);
}

template <typename T>
void codegen_ppc64le<T>::macro$branch$conditional$overflow(gen_context &ctx) {
    // Skip to last instruction if OF has already been evaluated
    ctx.assembler->bc(BO::FIELD_SET, CR_LAZYVALID_OVERFLOW, 20 * 4);

    // Allocate scratch registers for use in calculation
    gpr_t scratch1 = ctx.reg_allocator().allocate_gpr();

    // Branch to calculation code for operation type
    ctx.assembler->rldicl(0, GPR_FIXED_FLAG_OP_TYPE, 64-(uint32_t)LastFlagOpData::OP_TYPE_SHIFT, 64-2, false); // Extract FLAG_OP_TYPE[15:14] into r0
    ctx.assembler->cmpldi(CR_SCRATCH, 0, (uint32_t)LastFlagOpData::OP_ADD >> (uint32_t)LastFlagOpData::OP_TYPE_SHIFT);
    ctx.assembler->bc(BO::FIELD_SET, 4*CR_SCRATCH+assembler::CR_LT, 8 * 4); // Less than ADD -> SUB
    ctx.assembler->bc(BO::FIELD_SET, 4*CR_SCRATCH+assembler::CR_EQ, 2 * 4); // Equal to ADD
    ctx.assembler->invalid(); // Emit an invalid instruction to assert not reached

    { // ADD
        ctx.assembler->add(scratch1, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2);
        ctx.assembler->eqv(0, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2);
        ctx.assembler->_xor(scratch1, scratch1, GPR_FIXED_FLAG_OP2);
        ctx.assembler->_and(0, 0, scratch1);
        ctx.assembler->b(5 * 4); // Branch to common shifting code
    }

    { // SUB
        ctx.assembler->sub(scratch1, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2);
        ctx.assembler->_xor(0, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2);
        ctx.assembler->eqv(scratch1, scratch1, GPR_FIXED_FLAG_OP2);
        ctx.assembler->_and(0, 0, scratch1);
        // fall through to common shifting code
    }

    // The overflow bit is now in r0. Depending on operation width, shift it into bit 0, and clear all left.
    ctx.assembler->rldicl(scratch1, GPR_FIXED_FLAG_OP_TYPE, 64-(uint32_t)LastFlagOpData::OVERFLOW_SHIFT, 64-6, false);
    ctx.assembler->rldcl(0, 0, scratch1, 63, false); // Put overflow flag into r0[0]
    ctx.assembler->cmpldi(CR_SCRATCH, 0, 1);

    ctx.reg_allocator().free_gpr(scratch1);

    // CR_SCRATCH[eq] now contains the Overflow flag. Move it into CR_LAZY[OVERFLOW].
    ctx.assembler->crmove(CR_LAZY_FIELD_OVERFLOW, 4*CR_SCRATCH + assembler::CR_EQ);

    // Mark OF as valid
    ctx.assembler->crset(CR_LAZYVALID_OVERFLOW);
}

template <typename T>
void codegen_ppc64le<T>::macro$mask_register(assembler &assembler, gpr_t dest, gpr_t src, llir::Register::Mask mask,
                                             bool invert, bool modify_cr) {
    if (invert) {
        // Mask out all requested bits
        switch (mask) {
            case llir::Register::Mask::Full64:
            case llir::Register::Mask::Low32:
                TODO();
            case llir::Register::Mask::LowLow16:
                assembler.rldicr(dest, src, 0, 63-16, modify_cr);
                break;
            case llir::Register::Mask::LowLowHigh8:
                assembler.rldicl(dest, src, 48, 8, modify_cr);
                assembler.rldicl(dest, src, 16, 0, modify_cr);
                break;
            case llir::Register::Mask::LowLowLow8:
                assembler.rldicr(dest, src, 0, 63-8, modify_cr);
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
                assembler.rldicl(dest, src, 0, 32, modify_cr);
                break;
            case llir::Register::Mask::LowLow16:
                assembler.rldicl(dest, src, 0, 48, modify_cr);
                break;
            case llir::Register::Mask::LowLowHigh8:
                TODO();
                //assembler.rldicl(reg, reg, 64-8, 56, false);
            case llir::Register::Mask::LowLowLow8:
                assembler.rldicl(dest, src, 0, 56, modify_cr);
                break;
            default:
                TODO();
        }
    }
}

template <typename T>
void codegen_ppc64le<T>::macro$move_register_masked(assembler &assembler, gpr_t dest, gpr_t src, llir::Register::Mask src_mask,
                                                    llir::Register::Mask dest_mask, bool zero_others, bool modify_cr) {
    auto get_width_from_mask = [](auto mask) -> uint8_t {
        switch (mask) {
            case llir::Register::Mask::Full64: return 64;
            case llir::Register::Mask::Low32: return 32;
            case llir::Register::Mask::LowLow16: return 16;
            case llir::Register::Mask::LowLowHigh8: return 8;
            case llir::Register::Mask::LowLowLow8: return 8;
            default: TODO();
        }
    };

    auto get_shift_from_mask = [](auto mask) -> uint8_t {
        switch (mask) {
            case llir::Register::Mask::Full64:
            case llir::Register::Mask::Low32:
            case llir::Register::Mask::LowLow16:
            case llir::Register::Mask::LowLowLow8:
                return 0;
            case llir::Register::Mask::LowLowHigh8:
                return 8;
            default: TODO();
        }
    };
    uint8_t src_width = get_width_from_mask(src_mask);
    uint8_t src_shift = get_shift_from_mask(src_mask);
    uint8_t dest_width = get_width_from_mask(dest_mask);
    uint8_t dest_shift = get_shift_from_mask(dest_mask);

    if (zero_others) {
        // If we don't care about preserving others, we can get away with an rldicl
        uint8_t sh = (uint8_t)(64 - src_shift + dest_shift) % 64;
        uint8_t me = (uint8_t)(64 - std::min(dest_width, src_width) - dest_shift);

        assembler.rldicl(dest, src, sh, me, modify_cr);

        // If the destination isn't right-justified, clear the extra right bits
        if (dest_shift)
            assembler.rldicr(dest, dest, 0, 64-dest_shift, modify_cr);

        // If the source is smaller than the destination, clear the difference
        if (src_width < dest_width)
            assembler.rldicl(dest, dest, 0, (uint8_t)(64-dest_width-dest_shift), modify_cr);
    } else {
        if (!src_shift) {
            // If the source isn't shifted, this can be accomplished with rldimi
            assembler.insrdi(dest, src, dest_width, (uint8_t)(64-(dest_width + dest_shift)), modify_cr);

            if (dest_width > src_width) {
                // Extra bits were copied, clear high order
                // Test: 8 moved into 16
                assembler.rldicl(dest, dest, (uint8_t)(64-(dest_width+dest_shift)), src_width, false);
                assembler.rldicl(dest, dest, (uint8_t)(64-(64-(dest_width+dest_shift))), 0, modify_cr);
            }
        } else { TODO(); }
    }
}

// Explicitly instantiate for all supported traits
template class retrec::codegen_ppc64le<ppc64le::target_traits_x86_64>;
