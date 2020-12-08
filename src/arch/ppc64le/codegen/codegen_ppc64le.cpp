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

                case llir::Alu::Op::ADD:
                    llir$alu$add(ctx, insn);
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
                case llir::Branch::Op::X86_GREATER:
                case llir::Branch::Op::X86_LESS_EQ:
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

        case llir::Insn::Class::LOADSTORE:
            switch (insn.loadstore.op) {
                case llir::LoadStore::Op::LOAD:
                case llir::LoadStore::Op::STORE:
                case llir::LoadStore::Op::LEA:
                    llir$loadstore(ctx, insn);
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
                        pr_error("Unable to resolve Immediate Branch to target 0x%x\n", target);
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
llir::Register::Mask codegen_ppc64le<T>::llir$alu$helper$target_mask(llir::Register::Mask src_mask) {
    switch (src_mask) {
        case llir::Register::Mask::Full64:
        case llir::Register::Mask::Low32:
        case llir::Register::Mask::LowLow16:
        case llir::Register::Mask::LowLowLow8:
            return src_mask;
        case llir::Register::Mask::LowLowHigh8:
            return llir::Register::Mask::LowLowLow8;
        default:
            TODO();
    }
}

template <typename T>
llir::Register::Mask codegen_ppc64le<T>::llir$alu$helper$mask_from_width(llir::Operand::Width w) {
    switch (w) {
        case llir::Operand::Width::_8BIT: return llir::Register::Mask::LowLowLow8;
        case llir::Operand::Width::_16BIT: return llir::Register::Mask::LowLow16;
        case llir::Operand::Width::_32BIT: return llir::Register::Mask::Low32;
        case llir::Operand::Width::_64BIT: return llir::Register::Mask::Full64;
        default: TODO();
    }
}

template <typename T>
void codegen_ppc64le<T>::llir$alu$helper$load_operand_into_gpr(gen_context &ctx, const llir::Insn &insn,
                                                               const llir::Operand &op, gpr_t target) {
    switch (op.type) {
        case llir::Operand::Type::REG:
        {
            // Operand is in a register, move it to the target reg and mask it
            auto gpr = ctx.reg_allocator().get_fixed_gpr(op.reg);
            auto target_mask = llir$alu$helper$target_mask(op.reg.mask);
            macro$move_register_masked(*ctx.assembler, target, gpr.gpr(), op.reg.mask, target_mask, true, false);
            break;
        }

        case llir::Operand::Type::IMM:
            // Operand is an immediate, load it into the target reg
            macro$load_imm(*ctx.assembler, target, op.imm, llir$alu$helper$mask_from_width(op.width), true);
            break;

        case llir::Operand::Type::MEM:
            // Operand is in memory, load it into the target reg
            macro$loadstore(ctx, target, op.memory, llir::LoadStore::Op::LOAD, llir$alu$helper$mask_from_width(op.width), &insn);
            break;

        default:
            TODO();
    }
}

template <typename T>
void codegen_ppc64le<T>::llir$alu$helper$finalize_op(gen_context &ctx, const llir::Insn &insn, LastFlagOp op) {
    if (insn.dest_cnt) {
        auto res_mask = llir$alu$helper$target_mask(insn.dest[0].reg.mask);

        switch(insn.dest[0].type) {
            case llir::Operand::Type::REG:
            {
                // Copy result to destination register
                auto dest = ctx.reg_allocator().get_fixed_gpr(insn.dest[0].reg);

                macro$move_register_masked(*ctx.assembler, dest.gpr(), GPR_FIXED_FLAG_RES, res_mask,
                                           insn.dest[0].reg.mask, insn.dest[0].reg.zero_others, false);
                break;
            }

            case llir::Operand::Type::MEM:
                // Store result to memory
                macro$loadstore(ctx, GPR_FIXED_FLAG_RES, insn.dest[0].memory, llir::LoadStore::Op::STORE, res_mask, &insn);
                break;

            default:
                TODO();
        }

    }

    auto mask = llir$alu$helper$mask_from_width(insn.src[0].width);
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

    auto alu_flag_to_lazyvalid = [](llir::Alu::Flag f) -> std::optional<uint8_t> {
        switch (f) {
            case llir::Alu::Flag::CARRY:
                return CR_LAZYVALID_CARRY;
            case llir::Alu::Flag::OVERFLOW:
                return CR_LAZYVALID_OVERFLOW;
            default:
                return std::nullopt;
        }
    };

    // Set lazy flag status according to operation type
    if (insn.alu.flags_modified == llir::Alu::all_flags) {
        // All flags modified, wipe CR_LAZYVALID
        ctx.assembler->mcrf(CR_LAZYVALID, CR_ZEROS);
    } else {
        // Wipe affected flags one by one
        llir::Alu::IterateFlags(insn.alu.flags_modified, [&](auto flag) {
            auto lazyvalid_field = alu_flag_to_lazyvalid(flag);
            if (!lazyvalid_field)
                return;

            ctx.assembler->crclr(*lazyvalid_field);
        });
    }
}

template <typename T>
llir::Alu::FlagArr codegen_ppc64le<T>::llir$alu$helper$preserve_flags(gen_context &ctx, const llir::Insn &insn) {
    if (!insn.alu.modifies_flags)
        return {};

    // If this operation preserves any flags generated by Rc=1, we need to back them up and restore at the end
    llir::Alu::FlagArr preserved;
    size_t preserved_i = 0;

    llir::Alu::IterateFlags(llir$alu$all_rc0_flags, [&](auto flag) {
        bool found = std::find(insn.alu.flags_modified.begin(), insn.alu.flags_modified.end(), flag)
                        != insn.alu.flags_modified.end();
        if (!found) {
            // Flag wasn't found in the insn's list of modified flags - we need to preserve it
            preserved[preserved_i++] = flag;
        }
    });

    // Move cr0 to CR_SCRATCH, so $restore_flags can restore them later
    ctx.assembler->mcrf(CR_SCRATCH, 0);

    return preserved;
}

template <typename T>
void codegen_ppc64le<T>::llir$alu$helper$restore_flags(gen_context &ctx, llir::Alu::FlagArr &flags) {
    if (flags == llir$alu$all_rc0_flags) {
        // Optimization: if all rc0 flags need to be restored, just move CR_SCRATCH to cr0
        ctx.assembler->mcrf(0, CR_SCRATCH);
        return;
    }

    llir::Alu::IterateFlags(flags, [&](auto flag) {
        switch (flag) {
            case llir::Alu::Flag::SIGN:
                // Restore LT,GT
                ctx.assembler->crmove(assembler::CR_LT, CR_SCRATCH*4+assembler::CR_LT);
                ctx.assembler->crmove(assembler::CR_LT, CR_SCRATCH*4+assembler::CR_GT);
                break;

            case llir::Alu::Flag::ZERO:
                // Restore EQ
                ctx.assembler->crmove(assembler::CR_EQ, CR_SCRATCH*4+assembler::CR_EQ);
                break;

            default:
                break;
        }
    });
}

template <typename T>
void codegen_ppc64le<T>::llir$alu$load_imm(gen_context &ctx, const llir::Insn &insn) {
    pr_debug("alu$load_imm\n");
    assert(insn.dest_cnt == 1);
    assert(insn.dest[0].type == llir::Operand::Type::REG);
    assert(insn.src_cnt == 1);
    assert(insn.src[0].type == llir::Operand::Type::IMM);

    auto rt = ctx.reg_allocator().get_fixed_gpr(insn.dest[0].reg);

    macro$load_imm(*ctx.assembler, rt.gpr(), insn.src[0].imm, insn.dest[0].reg.mask, insn.dest[0].reg.zero_others);
}

template <typename T>
void codegen_ppc64le<T>::llir$alu$sub(gen_context &ctx, const llir::Insn &insn) {
    pr_debug("alu$sub\n");
    assert(insn.src_cnt == 2);
    auto width = insn.src[0].width;

    // Preserve flags
    llir::Alu::FlagArr preserved = llir$alu$helper$preserve_flags(ctx, insn);

    // Ensure all operands are in registers
    llir$alu$helper$load_operand_into_gpr(ctx, insn, insn.src[0], GPR_FIXED_FLAG_OP1);
    llir$alu$helper$load_operand_into_gpr(ctx, insn, insn.src[1], GPR_FIXED_FLAG_OP2);

    if (insn.alu.modifies_flags && width == llir::Operand::Width::_64BIT)
        ctx.assembler->sub_(GPR_FIXED_FLAG_RES, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2);
    else
        ctx.assembler->sub(GPR_FIXED_FLAG_RES, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2);

    // Restore flags
    llir$alu$helper$restore_flags(ctx, preserved);

    // Finalize operation
    llir$alu$helper$finalize_op(ctx, insn, LastFlagOp::SUB);
}

template <typename T>
void codegen_ppc64le<T>::llir$alu$add(gen_context &ctx, const llir::Insn &insn) {
    pr_debug("alu$add\n");
    assert(insn.src_cnt == 2);
    auto width = insn.src[0].width;

    // Preserve flags
    llir::Alu::FlagArr preserved;
    if (insn.alu.modifies_flags)
        preserved = llir$alu$helper$preserve_flags(ctx, insn);

    // Ensure all operands are in registers
    llir$alu$helper$load_operand_into_gpr(ctx, insn, insn.src[0], GPR_FIXED_FLAG_OP1);
    llir$alu$helper$load_operand_into_gpr(ctx, insn, insn.src[1], GPR_FIXED_FLAG_OP2);

    if (insn.alu.modifies_flags && width == llir::Operand::Width::_64BIT)
        ctx.assembler->add_(GPR_FIXED_FLAG_RES, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2);
    else
        ctx.assembler->add(GPR_FIXED_FLAG_RES, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2);

    // Restore flags
    if (insn.alu.modifies_flags)
        llir$alu$helper$restore_flags(ctx, preserved);

    // Finalize operation
    llir$alu$helper$finalize_op(ctx, insn, LastFlagOp::ADD);
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

        case llir::Branch::Op::X86_LESS_EQ: bo = BO::FIELD_CLR; goto greater_common;
        case llir::Branch::Op::X86_GREATER: bo = BO::FIELD_SET; goto greater_common;
        greater_common:
            // Relies on a combination of flags, one of which is lazily evaluated (OF)
            macro$branch$conditional$overflow(ctx);

            // (!ZF && (SF == OF)) can be implemented with NOR(ZF, XOR(SF, OF))
            ctx.assembler->crxor(CR_SCRATCH*4+1, CR_LAZY_FIELD_OVERFLOW, 0*4+assembler::CR_LT); // cr_scratch[1] = !(SF == OF)
            ctx.assembler->crnor(CR_SCRATCH*4+0, CR_SCRATCH*4+1, 0*4+assembler::CR_EQ);         // cr_scratch[0] = !cr_scratch[1] && !ZF
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

    auto scratch = ctx.reg_allocator().allocate_gpr();

    // Store address of callback
    macro$load_imm(*ctx.assembler, scratch.gpr(), (uint16_t)runtime_context_ppc64le::NativeTarget::SYSCALL, llir::Register::Mask::Full64, true);
    ctx.assembler->std(scratch.gpr(), GPR_FIXED_RUNTIME_CTX, offsetof(runtime_context_ppc64le, native_function_call_target));

    // Load arch_leave_translated_code
    ctx.assembler->ld(scratch.gpr(), GPR_FIXED_RUNTIME_CTX, offsetof(runtime_context_ppc64le, leave_translated_code_ptr));
    ctx.assembler->mtspr(SPR::CTR, scratch.gpr());

    // Save LR
    ctx.assembler->mfspr(scratch.gpr(), SPR::LR);
    ctx.assembler->std(scratch.gpr(), GPR_FIXED_RUNTIME_CTX, TRANSLATED_CTX_OFF(lr));

    // Branch
    ctx.assembler->bctrl();
}

template <typename T>
void codegen_ppc64le<T>::llir$loadstore(gen_context &ctx, const llir::Insn &insn) {
    pr_debug("$loadstore\n");
    assert(insn.dest_cnt == 1);
    assert(insn.src_cnt == 1);
    assert(!insn.loadstore.sign_extension); // FIXME

    // Extract memory and register operands
    auto &memory_operand = (insn.loadstore.op == llir::LoadStore::Op::STORE) ? insn.dest[0] : insn.src[0];
    assert(memory_operand.type == llir::Operand::Type::MEM);

    auto &reg_operand = (insn.loadstore.op == llir::LoadStore::Op::STORE) ? insn.src[0] : insn.dest[0];
    typename T::RegisterAllocatorT::AllocatedGprT reg;
    llir::Register::Mask reg_mask;

    switch (reg_operand.type) {
        case llir::Operand::Type::REG:
            reg = ctx.reg_allocator().get_fixed_gpr(reg_operand.reg);
            reg_mask = reg_operand.reg.mask;
            break;

        case llir::Operand::Type::IMM:
            assert(insn.loadstore.op == llir::LoadStore::Op::STORE);
            // Stores may also be performed from an immediate rather than a register.
            // Allocate a temporary register and load the immediate to it.
            reg = ctx.reg_allocator().allocate_gpr();
            reg_mask = llir$alu$helper$mask_from_width(reg_operand.width);
            macro$load_imm(*ctx.assembler, reg.gpr(), reg_operand.imm, llir::Register::Mask::Full64, true);
            break;

        case llir::Operand::Type::MEM:
            assert(insn.loadstore.op == llir::LoadStore::Op::STORE);
            // To support push [mem] we also have to support memory operands for stores
            reg = ctx.reg_allocator().allocate_gpr();
            reg_mask = llir$alu$helper$mask_from_width(reg_operand.width);
            macro$loadstore(ctx, reg.gpr(), reg_operand.memory, llir::LoadStore::Op::LOAD, reg_mask, nullptr);
            break;
    }

    // Emit load/store for the provided register and memory operands
    macro$loadstore(ctx, reg.gpr(), memory_operand.memory, insn.loadstore.op, reg_mask, &insn);
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
void codegen_ppc64le<T>::macro$alu$add_imm(gen_context &ctx, gpr_t dest, int64_t imm) {
    if (imm_fits_in<int16_t>(imm)) {
        ctx.assembler->addi(dest, dest, (int16_t)imm);
    } else {
        // If we can't use addi, load the immediate into a temporary
        auto temp = ctx.reg_allocator().allocate_gpr();
        macro$load_imm(*ctx.assembler, temp.gpr(), imm, llir::Register::Mask::Full64, true);
        ctx.assembler->add(dest, dest, temp.gpr());
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
    {
        auto scratch = ctx.reg_allocator().allocate_gpr();
        ctx.assembler->lnia(scratch.gpr());
        ctx.assembler->add(0, 0, scratch.gpr());
    }
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
    auto scratch1 = ctx.reg_allocator().allocate_gpr();

    // Branch to calculation code for operation type
    ctx.assembler->rldicl(0, GPR_FIXED_FLAG_OP_TYPE, 64-(uint32_t)LastFlagOpData::OP_TYPE_SHIFT, 64-2, false); // Extract FLAG_OP_TYPE[15:14] into r0
    ctx.assembler->cmpldi(CR_SCRATCH, 0, (uint32_t)LastFlagOpData::OP_ADD >> (uint32_t)LastFlagOpData::OP_TYPE_SHIFT);
    ctx.assembler->bc(BO::FIELD_SET, 4*CR_SCRATCH+assembler::CR_LT, 8 * 4); // Less than ADD -> SUB
    ctx.assembler->bc(BO::FIELD_SET, 4*CR_SCRATCH+assembler::CR_EQ, 2 * 4); // Equal to ADD
    ctx.assembler->invalid(); // Emit an invalid instruction to assert not reached

    { // ADD
        ctx.assembler->add(scratch1.gpr(), GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2);
        ctx.assembler->eqv(0, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2);
        ctx.assembler->_xor(scratch1.gpr(), scratch1.gpr(), GPR_FIXED_FLAG_OP2);
        ctx.assembler->_and(0, 0, scratch1.gpr());
        ctx.assembler->b(5 * 4); // Branch to common shifting code
    }

    { // SUB
        ctx.assembler->sub(scratch1.gpr(), GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2);
        ctx.assembler->_xor(0, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2);
        ctx.assembler->eqv(scratch1.gpr(), scratch1.gpr(), GPR_FIXED_FLAG_OP2);
        ctx.assembler->_and(0, 0, scratch1.gpr());
        // fall through to common shifting code
    }

    // The overflow bit is now in r0. Depending on operation width, shift it into bit 0, and clear all left.
    ctx.assembler->rldicl(scratch1.gpr(), GPR_FIXED_FLAG_OP_TYPE, 64-(uint32_t)LastFlagOpData::OVERFLOW_SHIFT, 64-6, false);
    ctx.assembler->rldcl(0, 0, scratch1.gpr(), 63, false); // Put overflow flag into r0[0]
    ctx.assembler->cmpldi(CR_SCRATCH, 0, 1);

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
        } else {
            if (src_mask != llir::Register::Mask::Full64 && dest_mask != llir::Register::Mask::Full64) {
                // For <64-bit masks we can use rlwimi
                uint8_t sh = (uint8_t)(32 - src_shift + dest_shift) % 32;
                uint8_t mb = (uint8_t)(32 - std::min(dest_width, src_width) - dest_shift);
                uint8_t me = 31 - dest_shift;

                assembler.rlwimi(dest, src, sh, mb, me);
            } else { TODO(); }
        }
    }
}

template <typename T>
void codegen_ppc64le<T>::macro$loadstore(gen_context &, gpr_t,
                                         const llir::MemOp &, llir::LoadStore::Op,
                                         llir::Register::Mask, const llir::Insn *) {
    static_assert(std::is_same_v<T, T>, "Missing macro$loadstore specialization for target arch!");
}


// Specialization of macro$loadstore for x86_64 targets
template <>
void codegen_ppc64le<ppc64le::target_traits_x86_64>::macro$loadstore(gen_context &ctx, gpr_t reg,
                     const llir::MemOp &mem, llir::LoadStore::Op op, llir::Register::Mask reg_mask,
                     const llir::Insn *insn) {
    assert(mem.arch == Architecture::X86_64);
    auto update = insn ? insn->loadstore.update : llir::LoadStore::Update::NONE;

    auto disp_fits = [&](auto disp) -> bool {
        if (op == llir::LoadStore::Op::LEA || reg_mask != llir::Register::Mask::Full64)
            // For LEA or <64-bit loads/stores, check if the mask fits in 16-bit addi/l{b,h,w}z disp field
            return assembler::fits_in_mask(disp, 0xFFFFU);
        else
            // For 64-bit loads/stores, the displacement must have the two least significant bits cleared
            return assembler::fits_in_mask(disp, 0xFFFCU);
    };

// Helpers to call the appropriate loadstore op depending on whether `update` is set or not
#define LOADSTORE_DISP(op, ...) ((update == llir::LoadStore::Update::PRE) ? ctx.assembler->op ## u(__VA_ARGS__) : ctx.assembler->op(__VA_ARGS__))
#define LOADSTORE_INDEXED(op, ...) ((update == llir::LoadStore::Update::PRE) ? ctx.assembler->op ## ux(__VA_ARGS__) : ctx.assembler->op ## x(__VA_ARGS__))

    auto loadstore_disp = [&](gpr_t reg, gpr_t ra, int16_t disp) {
        if (op == llir::LoadStore::Op::LOAD) {
            switch (reg_mask) {
                case llir::Register::Mask::Full64: LOADSTORE_DISP(ld, reg, ra, disp); break;
                case llir::Register::Mask::Low32: LOADSTORE_DISP(lwz, reg, ra, disp); break;
                case llir::Register::Mask::LowLow16: LOADSTORE_DISP(lhz, reg, ra, disp); break;
                case llir::Register::Mask::LowLowLow8: LOADSTORE_DISP(lbz, reg, ra, disp); break;
                case llir::Register::Mask::LowLowHigh8:
                {
                    // FIXME: There's probably a more intelligent way to do this
                    auto temp = ctx.reg_allocator().allocate_gpr();
                    LOADSTORE_DISP(lbz, temp.gpr(), ra, disp);
                    macro$move_register_masked(*ctx.assembler, reg, temp.gpr(),
                                               llir::Register::Mask::LowLowLow8,
                                               llir::Register::Mask::LowLowHigh8, false, false);
                    break;
                }
                case llir::Register::Mask::Special: TODO();
            }
        } else if (op == llir::LoadStore::Op::STORE) {
            switch (reg_mask) {
                case llir::Register::Mask::Full64: LOADSTORE_DISP(std, reg, ra, disp); break;
                case llir::Register::Mask::Low32: LOADSTORE_DISP(stw, reg, ra, disp); break;
                case llir::Register::Mask::LowLow16: LOADSTORE_DISP(sth, reg, ra, disp); break;
                case llir::Register::Mask::LowLowLow8: LOADSTORE_DISP(stb, reg, ra, disp); break;
                case llir::Register::Mask::LowLowHigh8:
                {
                    auto temp = ctx.reg_allocator().allocate_gpr();
                    macro$move_register_masked(*ctx.assembler, temp.gpr(), reg,
                                               llir::Register::Mask::LowLowHigh8,
                                               llir::Register::Mask::LowLowLow8, false, false);
                    LOADSTORE_DISP(stb, temp.gpr(), ra, disp);
                    break;
                }
                case llir::Register::Mask::Special: TODO();
            }
        } else if (op == llir::LoadStore::Op::LEA) {
            // Load calculated address into reg
            ctx.assembler->addi(reg, ra, disp);
        } else { TODO(); }
    };

    auto loadstore_indexed = [&](gpr_t reg, gpr_t ra, gpr_t rb) {
        if (op == llir::LoadStore::Op::LOAD) {
            switch (reg_mask) {
                case llir::Register::Mask::Full64: LOADSTORE_INDEXED(ld, reg, ra, rb); break;
                case llir::Register::Mask::Low32: LOADSTORE_INDEXED(lwz, reg, ra, rb); break;
                case llir::Register::Mask::LowLow16: LOADSTORE_INDEXED(lhz, reg, ra, rb); break;
                case llir::Register::Mask::LowLowLow8: LOADSTORE_INDEXED(lbz, reg, ra, rb); break;
                case llir::Register::Mask::LowLowHigh8:
                {
                    auto temp = ctx.reg_allocator().allocate_gpr();
                    LOADSTORE_INDEXED(lbz, temp.gpr(), ra, rb);
                    macro$move_register_masked(*ctx.assembler, reg, temp.gpr(),
                                               llir::Register::Mask::LowLowLow8,
                                               llir::Register::Mask::LowLowHigh8, false, false);
                    break;
                }
                case llir::Register::Mask::Special: TODO();
            }
        } else if (op == llir::LoadStore::Op::STORE) {
            switch (reg_mask) {
                case llir::Register::Mask::Full64: LOADSTORE_INDEXED(std, reg, ra, rb); break;
                case llir::Register::Mask::Low32: LOADSTORE_INDEXED(stw, reg, ra, rb); break;
                case llir::Register::Mask::LowLow16: LOADSTORE_INDEXED(sth, reg, ra, rb); break;
                case llir::Register::Mask::LowLowLow8: LOADSTORE_INDEXED(stb, reg, ra, rb); break;
                case llir::Register::Mask::LowLowHigh8:
                {
                    auto temp = ctx.reg_allocator().allocate_gpr();
                    macro$move_register_masked(*ctx.assembler, temp.gpr(), reg,
                                               llir::Register::Mask::LowLowHigh8,
                                               llir::Register::Mask::LowLowLow8, false, false);
                    LOADSTORE_INDEXED(stb, temp.gpr(), ra, rb);
                    break;
                }
                case llir::Register::Mask::Special: TODO();
            }
        } else if (op == llir::LoadStore::Op::LEA) {
            // Load calculated address into reg
            ctx.assembler->add(reg, ra, rb);
        } else { TODO(); }
    };

#undef LOADSTORE_DISP
#undef LOADSTORE_INDEXED

    auto loadstore_disp_auto = [&](gpr_t reg, gpr_t ra, int64_t disp) {
        if (disp_fits(disp)) {
            // Fits in an immediate displacement field
            loadstore_disp(reg, ra, (int16_t)disp);
        } else {
            // Need to load into a gpr before operation
            auto temp = ctx.reg_allocator().allocate_gpr();
            macro$load_imm(*ctx.assembler, temp.gpr(), disp, llir::Register::Mask::Full64, true);
            loadstore_indexed(reg, ra, temp.gpr());
        }
    };

    auto scale_reg = [&](auto index, auto &memop) {
        auto temp = ctx.reg_allocator().allocate_gpr();
        switch (memop.x86_64.scale) {
            case 2:
                ctx.assembler->sldi(temp.gpr(), index.gpr(), 1);
                return temp;
            case 4:
                ctx.assembler->sldi(temp.gpr(), index.gpr(), 2);
                return temp;
            case 8:
                ctx.assembler->sldi(temp.gpr(), index.gpr(), 3);
                return temp;
        }

        // No scale required
        return index;
    };

    auto &x86_64 = mem.x86_64;
    typename target_traits_x86_64::RegisterAllocatorT::AllocatedGprT base, index;

    // Obtain GPRs for base and index if present
    if (x86_64.base.x86_64 != llir::X86_64Register::INVALID) {
        if (x86_64.base.x86_64 == llir::X86_64Register::RIP) {
            // Special case: RIP-relative addressing
            // Load the next instruction's address into a temporary GPR and use that as base
            assert(insn); // Using RIP-rel addressing without providing an insn is invalid
            base = ctx.reg_allocator().allocate_gpr();
            uint64_t next_rip = insn->address + insn->size;
            macro$load_imm(*ctx.assembler, base.gpr(), next_rip, llir::Register::Mask::Full64, true);
        } else {
            base = ctx.reg_allocator().get_fixed_gpr(x86_64.base);
        }
    }
    if (x86_64.index.x86_64 != llir::X86_64Register::INVALID)
        index = ctx.reg_allocator().get_fixed_gpr(x86_64.index);

    // Sanity checks
    if (update != llir::LoadStore::Update::NONE) {
        // For loads/stores with update, only base should be present and disp should be non-zero
        assert(base);
        assert(!index);
        assert(x86_64.disp);
    }

    // Perform operation depending on available operands
    if (base && index) {
        // Both base and index registers are present
        auto scaled_index = scale_reg(std::move(index), mem);
        if (!x86_64.disp) {
            // Optimization: If no displacement is present, used an indexed load/store
            loadstore_indexed(reg, base.gpr(), scaled_index.gpr());
        } else {
            // Store base+scaled_index in an intermediate reg and use a displacement load/store
            auto intermediate_reg = ctx.reg_allocator().allocate_gpr();
            ctx.assembler->add(intermediate_reg.gpr(), base.gpr(), scaled_index.gpr());

            loadstore_disp_auto(reg, intermediate_reg.gpr(), x86_64.disp);
        }
    } else if (base) {
        // Only base is present - use a displacement load/store
        if (update == llir::LoadStore::Update::POST) {
            // Special case for POST update - use 0 disp and add disp to base.gpr() after
            loadstore_disp_auto(reg, base.gpr(), 0);
            macro$alu$add_imm(ctx, base.gpr(), x86_64.disp);
        } else {
            loadstore_disp_auto(reg, base.gpr(), x86_64.disp);
        }
    } else if (index) {
        // Only index is present - scale it and use a displacement load/store
        auto scaled_index = scale_reg(std::move(index), mem);
        loadstore_disp_auto(reg, scaled_index.gpr(), x86_64.disp);
    } else {
        // Neither register is present, do a displacement load/store off of the immediate
        loadstore_disp_auto(reg, 0, x86_64.disp);
    }
}

// Explicitly instantiate for all supported traits
template class retrec::codegen_ppc64le<ppc64le::target_traits_x86_64>;
