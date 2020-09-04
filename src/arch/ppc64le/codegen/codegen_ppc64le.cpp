#include <arch/ppc64le/codegen/codegen_ppc64le.h>

#include <capstone.h>
#include <disassembler.h>
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
    switch (insn.iclass) {
        case llir::Insn::Class::ALU:
            switch (insn.alu.op) {
                case llir::Alu::Op::LOAD_IMM:
                    llir$alu$load_imm(ctx, insn);
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
        switch (relocation.type) {
            case Relocation::Type::BRANCH_REL24:
            {
                // Resolve branch target
                auto target = ctx.local_branch_targets.find(relocation.data);
                if (target == ctx.local_branch_targets.end())
                    return status_code::BADBRANCH;

                size_t old_pos = ctx.code_buffer.pos();
                ctx.code_buffer.set_pos(relocation.offset);

                uint64_t my_address = (uint64_t) ctx.code_buffer.start() + relocation.offset;
                macro$branch$unconditional(ctx.assembler, my_address, target->second);

                ctx.code_buffer.set_pos(old_pos);

                break;
            }

            default:
                TODO();
        }
    }

    return status_code::SUCCESS;
}

//
// Codegen routines for all supported LLIR instructions
//

template <typename T>
void codegen_ppc64le<T>::llir$alu$load_imm(gen_context &ctx, const llir::Insn &insn) {
    assert(insn.dest_cnt == 1);
    assert(insn.dest[0].type == llir::Operand::Type::REG);
    assert(insn.src_cnt == 1);
    assert(insn.src[0].type == llir::Operand::Type::IMM);
    ctx.local_branch_targets.insert({ insn.address, ctx.code_buffer.pos_addr() });

    gpr_t rt = reg_allocator.allocate_gpr(insn.dest[0].reg);
    assert(rt != GPR_INVALID);

    macro$load_imm(ctx.assembler, rt, insn.src[0].imm);

    if (insn.dest[0].reg.mask != llir::Register::Mask::Full64 && !insn.dest[0].reg.zero_others) {
        // The llir specifies that bits outside mask should be kept. Implement this.
        TODO();
    }
}

/**
 * Return target virtual address for given branch
 */
template <typename T>
int64_t codegen_ppc64le<T>::resolve_branch_target(const llir::Insn &insn) {
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
    assert(insn.dest_cnt == 0);
    assert(insn.src_cnt == 1);
    ctx.local_branch_targets.insert({ insn.address, ctx.code_buffer.pos_addr() });

    if (insn.src[0].type == llir::Operand::Type::IMM) {
        int64_t target = resolve_branch_target(insn);

        // Experiment: always emit a relocation. This could make optimizations in later passes easier
        ctx.relocations.push_back({ctx.code_buffer.pos(), Relocation::Type::BRANCH_REL24, target});
        ctx.assembler.nop();
    } else {
        TODO();
    }
}

template <typename T>
void codegen_ppc64le<T>::llir$interrupt$syscall(gen_context &ctx, const llir::Insn &insn) {
    assert(insn.dest_cnt == 0 && insn.src_cnt == 0);
    ctx.local_branch_targets.insert({ insn.address, ctx.code_buffer.pos_addr() });
    ppc64le::assembler &assembler = ctx.assembler;

    // To handle a syscall, we have to re-enter native code, so emit a branch to arch_leave_translated_code.
    // Special considerations:
    // * arch_leave_translated code won't save LR for us, so we have to do it
    // * we need to store the callback in runtime_context(r11).host_native_context.native_function_call_target

    gpr_t scratch = reg_allocator.allocate_gpr();
    assert(scratch != GPR_INVALID);

    // Store address of callback
    macro$load_imm(assembler, scratch, (uint16_t)runtime_context_ppc64le::NativeTarget::SYSCALL);
    assembler.std(scratch, 11, offsetof(runtime_context_ppc64le, native_function_call_target));

    // Load arch_leave_translated_code
    macro$load_imm(assembler, scratch, (uint64_t)arch_leave_translated_code);
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
void codegen_ppc64le<T>::macro$load_imm(assembler &assembler, gpr_t dest, int64_t imm) {
    if (imm <= INT16_MAX && imm >= INT16_MIN) {
        // If the immediate fits in an int16_t, we can just emit an addi
        assembler.addi(dest, 0, imm);
    } else if (imm <= INT32_MAX && imm >= INT32_MIN) {
        // If the immediate fits in an int32_t, emit addis and ori
        assembler.addis(dest, 0, (imm >> 16) & 0xFFFF);
        assembler.ori(dest, dest, imm & 0xFFFFU);
    } else {
        // Do the full song and dance for a 64-bit immediate load. Eventually we should use a TOC.
        assembler.addis(dest, 0, (imm >> 48) & 0xFFFF);
        assembler.ori(dest, dest, (imm >> 32) & 0xFFFF);
        assembler.rldicr(dest, dest, 32, 31, false);
        assembler.oris(dest, dest, (imm >> 16) & 0xFFFF);
        assembler.ori(dest, dest, imm & 0xFFFF);
    }
}

template <typename T>
void codegen_ppc64le<T>::macro$branch$unconditional(assembler &assembler, uint64_t my_address, uint64_t target) {
    constexpr int32_t LI_FIELD_MAX =  0x1ffffff; // 2**(26-1) - 1
    constexpr int32_t LI_FIELD_MIN = -LI_FIELD_MAX - 1;

    int64_t diff = (int64_t)target - (int64_t)my_address;
    if (diff <= LI_FIELD_MAX && diff >= LI_FIELD_MIN) {
        // Target is close enough to emit a relative branch
        log(LOGL_INFO, "REL: %lld (0x%llx - 0x%llx)\n", diff, target, my_address);
        assembler.b(diff);
    } else if (target <= LI_FIELD_MAX) {
        // Target is in the first 26-bits of the address space
        log(LOGL_INFO, "ABS: 0x%lx\n", target);
        assembler.ba(target);
    } else {
        // Far branch. TODO.
        TODO();
    }
}

// Explicitly instantiate for all supported traits
template class retrec::codegen_ppc64le<ppc64le::target_traits_x86_64>;