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

#include <llir.h>
#include <arch/ppc64le/codegen/codegen_ppc64le.h>
#include <arch/ppc64le/codegen/codegen_types.h>
#include <arch/ppc64le/codegen/assembler.h>
#include <arch/ppc64le/codegen/abi.h>
#include <arch/x86_64/target_environment.h>

#include <type_traits>
#include <unordered_map>
#include <variant>
#include <cstring>

#include <sys/mman.h>

using namespace retrec;
using namespace retrec::ppc64le;

// Offset of a host_translated_context member from runtime_context
#define TRANSLATED_CTX_OFF(member) (uint16_t)(offsetof(runtime_context_ppc64le, host_translated_context) + \
                                              offsetof(cpu_context_ppc64le, member))

#if RETREC_DEBUG_BUILD

#include <fstream>
#include <iomanip>
const char *FUNCTION_MAP_OUTPUT_PATH = "retrec_codegen_ppc64le_map.txt";

template <typename T>
void codegen_ppc64le<T>::write_function_map(gen_context &ctx, uint64_t output_haddr) {
    static bool first = true;
    std::ofstream of;
    of.open(FUNCTION_MAP_OUTPUT_PATH, first ? std::ios_base::out : std::ios_base::app);
    if (first)
        first = false;

    auto find_vaddr = [&](size_t i) {
        for (const auto &pair : ctx.local_branch_targets) {
            if (pair.second == i)
                return pair.first;
        }
        return 0ul;
    };

    for (size_t i = 0; i < ctx.stream->size(); i++) {
        // Write the vaddr : haddr mapping for this insn
        uint64_t haddr = i * INSN_SIZE + output_haddr;
        uint64_t vaddr = find_vaddr(i);
        of << std::hex << std::setw(16) << std::setfill('0') << vaddr << " : " << haddr << "\n";
    }
}

#endif // RETREC_DEBUG_BUILD

template <typename T>
codegen_ppc64le<T>::gen_context::gen_context(virtual_address_mapper *vam_) : vam(vam_) {
    assembler = std::make_unique<ppc64le::assembler>();
    stream = std::make_unique<ppc64le::instruction_stream>(*assembler);
    assembler->set_stream(&*stream);
}

template <typename T>
codegen_ppc64le<T>::gen_context::~gen_context() {
    if (!vam)
        // Temporary constructor (no virtual address map), skip everything
        return;

    uint64_t base_addr = (uint64_t)stream->buf();
    assert(base_addr);

    // Insert all local (vaddr:haddr) pairs into the global virtual target map
    for (auto &pair : local_branch_targets) {
        vam->insert(pair.first, base_addr + pair.second*INSN_SIZE);
    }
}

template <typename T>
status_code codegen_ppc64le<T>::init() {
    constexpr size_t FUNCTION_TABLE_SIZE = 0x10000; // 64K

    // Allocate a function table at an address that can fit in the AA=1 LI field of I-form branch instructions
    constexpr process_memory_map::Range LI_RANGE = {0x10000, 0x3ff0000};
    void *function_table;
    auto res = econtext.allocate_and_map_vaddr(LI_RANGE, FUNCTION_TABLE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                                               &function_table);
    if (res != status_code::SUCCESS) {
        pr_debug("Failed to allocate function table: %s\n", status_code_str(res));
        return res;
    }

    if ((uintptr_t)function_table >= 0x3ffffff) {
        pr_debug("Function table was allocated too high. Address: %p", function_table);
        return status_code::NOMEM;
    }

    // First pass: Generate all fixed functions
    gen_context ctx(vam);

    auto alignment_padding = [&] {
        while (ctx.stream->size() & 0b11)
            ctx.assembler->invalid();
    };

    /* call */
    uint32_t call_offset = (uint32_t)(ctx.stream->size() * INSN_SIZE);
    fixed_helper$call$emit(ctx);
    alignment_padding();

    /* call_direct */
    uint32_t call_direct_offset = (uint32_t)(ctx.stream->size() * INSN_SIZE);
    fixed_helper$call_direct$emit(ctx, false);
    alignment_padding();

    /* call_direct_rel */
    uint32_t call_direct_rel_offset = (uint32_t)(ctx.stream->size() * INSN_SIZE);
    fixed_helper$call_direct$emit(ctx, true);
    alignment_padding();

    /* indirect_jmp */
    uint32_t indirect_jmp_offset = (uint32_t)(ctx.stream->size() * INSN_SIZE);
    fixed_helper$indirect_jmp$emit(ctx);
    alignment_padding();

    /* jmp_direct_rel */
    uint32_t jmp_direct_rel_offset = (uint32_t)(ctx.stream->size() * INSN_SIZE);
    fixed_helper$jmp_direct_rel$emit(ctx);
    alignment_padding();

    /* syscall */
    uint32_t syscall_offset = (uint32_t)(ctx.stream->size() * INSN_SIZE);
    fixed_helper$syscall$emit(ctx);
    alignment_padding();

    /* trap_patch_call */
    uint32_t trap_patch_call_offset = (uint32_t)(ctx.stream->size() * INSN_SIZE);
    fixed_helper$trap_patch_call$emit(ctx);
    alignment_padding();

    /* trap_patch_jump */
    uint32_t trap_patch_jump_offset = (uint32_t)(ctx.stream->size() * INSN_SIZE);
    fixed_helper$trap_patch_jump$emit(ctx);
    alignment_padding();

    /* imul_overflow */
    uint32_t imul_overflow_offset = (uint32_t)(ctx.stream->size() * INSN_SIZE);
    fixed_helper$imul_overflow$emit(ctx);
    alignment_padding();

    /* shift_carry */
    uint32_t shift_carry_offset = (uint32_t)(ctx.stream->size() * INSN_SIZE);
    fixed_helper$shift_carry$emit(ctx);
    alignment_padding();

    /* shift_overflow */
    uint32_t shift_overflow_offset = (uint32_t)(ctx.stream->size() * INSN_SIZE);
    fixed_helper$shift_overflow$emit(ctx);
    alignment_padding();

    /* cpuid */
    uint32_t cpuid_offset = (uint32_t)(ctx.stream->size() * INSN_SIZE);
    fixed_helper$cpuid$emit(ctx);
    alignment_padding();

    /* mul_overflow */
    uint32_t mul_overflow_offset = (uint32_t)(ctx.stream->size() * INSN_SIZE);
    fixed_helper$mul_overflow$emit(ctx);
    alignment_padding();

    // Second pass: resolve relocations
    res = resolve_relocations(ctx);
    if (res != status_code::SUCCESS) {
        pr_error("Failed to resolve relocations for generated code: %s!\n", status_code_str(res));
        return res;
    }

    // Third pass: Emit all generated instructions to a code buffer
    size_t code_size = ctx.stream->code_size();
    assert(code_size < FUNCTION_TABLE_SIZE);
    res = ctx.stream->emit_all_to_buf((uint8_t *)function_table, code_size);
    if (res != status_code::SUCCESS) {
        pr_error("Failed to emit instructions to code buffer: %s!\n", status_code_str(res));
        return res;
    }

    // Fill in function addresses
    ff_addresses.call = (uint32_t)(uintptr_t)function_table + call_offset;
    ff_addresses.call_direct = (uint32_t)(uintptr_t)function_table + call_direct_offset;
    ff_addresses.call_direct_rel = (uint32_t)(uintptr_t)function_table + call_direct_rel_offset;
    ff_addresses.indirect_jmp = (uint32_t)(uintptr_t)function_table + indirect_jmp_offset;
    ff_addresses.jmp_direct_rel = (uint32_t)(uintptr_t)function_table + jmp_direct_rel_offset;
    ff_addresses.syscall = (uint32_t)(uintptr_t)function_table + syscall_offset;
    ff_addresses.trap_patch_call = (uint32_t)(uintptr_t)function_table + trap_patch_call_offset;
    ff_addresses.trap_patch_jump = (uint32_t)(uintptr_t)function_table + trap_patch_jump_offset;
    ff_addresses.imul_overflow = (uint32_t)(uintptr_t)function_table + imul_overflow_offset;
    ff_addresses.shift_carry = (uint32_t)(uintptr_t)function_table + shift_carry_offset;
    ff_addresses.shift_overflow = (uint32_t)(uintptr_t)function_table + shift_overflow_offset;
    ff_addresses.cpuid = (uint32_t)(uintptr_t)function_table + cpuid_offset;
    ff_addresses.mul_overflow = (uint32_t)(uintptr_t)function_table + mul_overflow_offset;

    pr_debug("Emitted function table to %p\n", function_table);
    return status_code::SUCCESS;
}

template <typename T>
status_code codegen_ppc64le<T>::translate(const lifted_llir_block& llir, std::optional<translated_code_region> &out) {
    // First pass: dispatch and translate all LLIR instructions
    gen_context ctx(vam);
    for (const llir::Insn &insn : llir.get_insns()) {
        dispatch(ctx, insn);
    }
    emit_epilogue(ctx, llir);

    // Second pass: resolve relocations
    pr_debug("Resolving relocations!\n");
    status_code res = resolve_relocations(ctx);
    if (res != status_code::SUCCESS) {
        pr_error("Failed to resolve relocations for generated code: %s!\n", status_code_str(res));
        return res;
    }

    // Third pass: Emit all generated instructions to a code buffer
    size_t code_size = ctx.stream->code_size();
    void *code = econtext.get_code_allocator().allocate(code_size);
    if (!code) {
        pr_error("Failed to allocate suitably sized code buffer!\n");
        return status_code::NOMEM;
    }

    res = ctx.stream->emit_all_to_buf((uint8_t *)code, code_size);
    if (res != status_code::SUCCESS) {
        pr_error("Failed to emit instructions to code buffer: %s!\n", status_code_str(res));
        return res;
    }

    if constexpr(RETREC_DEBUG_BUILD)
        write_function_map(ctx, (uint64_t)code);

    // Return translated code region
    out = {code, code_size};

    return status_code::SUCCESS;
}

template <typename T>
void codegen_ppc64le<T>::emit_epilogue(gen_context &ctx, const lifted_llir_block &llir) {
    // The epilogue is reached when the block falls through to the end without branching elsewhere.
    // Emit a patched direct jmp to the address that is 1 past the last instruction in the block.
    auto last_insn = (llir.get_insns().end() - 1);
    uint64_t target_vaddr = last_insn->address + last_insn->size;
    macro$nop$relocation(ctx, DIRECT_JMP_PATCH_INSN_COUNT,
                         relocation{DIRECT_JMP_PATCH_INSN_COUNT, relocation::imm_rel_direct_jmp{target_vaddr}});
}

template <typename T>
uint64_t codegen_ppc64le<T>::get_last_untranslated_access(runtime_context &rctx) {
    switch (rctx.native_function_call_target) {
        case runtime_context_ppc64le::NativeTarget::JUMP:
        case runtime_context_ppc64le::NativeTarget::CALL:
            // Trap was for a CALL, so the target is in R0 (see fixed_helper$call)
            return rctx.host_translated_context.gprs[0];

        case runtime_context_ppc64le::NativeTarget::PATCH_CALL:
        case runtime_context_ppc64le::NativeTarget::PATCH_JUMP:
            // Trap was for a patch, the target is directly stored in the instruction stream
            return *(uint64_t *)rctx.host_translated_context.nip;

        default:
            TODO();
    }
}

template <typename T>
auto codegen_ppc64le<T>::calculate_pcrel_branch_patch_offsets(size_t patch_insn_count, int64_t target_off)
                                                              -> pcrel_branch_patch_offsets {
    pcrel_branch_patch_offsets res;

    // Recalculate the offset to be relative to bla's new LR, not the relocation's position
    res.imm_insn_count = llir$alu$helper$load_imm_insn_count(target_off);
    size_t tmp_end_nops = patch_insn_count - res.imm_insn_count - 1; /* 1 for bla */
    res.new_offset = target_off - res.imm_insn_count*INSN_SIZE - tmp_end_nops*INSN_SIZE;
    res.new_imm_insn_count = llir$alu$helper$load_imm_insn_count(res.new_offset);
    if (res.new_imm_insn_count > res.imm_insn_count) {
        // Sometimes modifying the immediate will affect the number of instructions required
        // to store it. In these cases, the original count must be the larger of the two and
        // the gap can be filled with NOPs.
        res.imm_insn_count = res.new_imm_insn_count;

        size_t tmp_end_nops = patch_insn_count - res.imm_insn_count - 1; /* 1 for bla */
        res.new_offset = target_off - res.imm_insn_count*INSN_SIZE - tmp_end_nops*INSN_SIZE;
        res.new_imm_insn_count = llir$alu$helper$load_imm_insn_count(res.new_offset);

        assert(res.new_imm_insn_count <= res.imm_insn_count);
    }
    assert(res.new_imm_insn_count <= patch_insn_count - 1 /* 1 for bla */);

    // Calculate amount of padding NOPs required
    res.middle_nops = res.imm_insn_count - res.new_imm_insn_count;
    res.end_nops = patch_insn_count - res.new_imm_insn_count - res.middle_nops - 1; /* 1 for bla */

    return res;
}

template <typename T>
status_code codegen_ppc64le<T>::patch_translated_access(runtime_context &rctx, uint64_t resolved_haddr) {
    int64_t &nip = rctx.host_translated_context.nip;

    switch (rctx.native_function_call_target) {
        case runtime_context_ppc64le::NativeTarget::PATCH_CALL:
        {
            pr_debug("Patching in DIRECT_CALL to host address 0x%lx\n", resolved_haddr);
            gen_context tmp_ctx(nullptr);

            // Load translated target into r0 and call relevant fixed_helper
            int64_t target_off = resolved_haddr - (nip - INSN_SIZE);

            // Recalculate the offset to be relative to bla's new LR, not the relocation's position
            auto offs = calculate_pcrel_branch_patch_offsets(DIRECT_CALL_PATCH_INSN_COUNT, target_off);

            // Load the immediate offset
            macro$load_imm(*tmp_ctx.assembler, 0, offs.new_offset, llir::Register::Mask::Full64, true);

            // Fill in NOPs if required to pad immediate's offset from the branch
            macro$nops(*tmp_ctx.assembler, offs.middle_nops);

            // Branch to $call_direct_rel
            tmp_ctx.assembler->bla(ff_addresses.call_direct_rel);

            // Fill in NOPs at the end
            macro$nops(*tmp_ctx.assembler, offs.end_nops);

            // Emit instructions to nip-4
            uint8_t *buffer_start = (uint8_t *)nip - INSN_SIZE;
            status_code res = tmp_ctx.stream->emit_all_to_buf(buffer_start, DIRECT_CALL_PATCH_INSN_COUNT*INSN_SIZE);
            if (res != status_code::SUCCESS) {
                pr_error("Failed to emit direct call patch: %s\n", status_code_str(res));
                return res;
            }

            // Rewind NIP to execute newly patched code
            nip = nip - INSN_SIZE;
            rctx.flush_icache = true;
            break;
        }

        case runtime_context_ppc64le::NativeTarget::PATCH_JUMP:
        {
            pr_debug("Patching in DIRECT_JUMP to host address 0x%lx\n", resolved_haddr);
            gen_context tmp_ctx(nullptr);

            // Load translated target into r0 and call relevant fixed_helper
            int64_t target_off = resolved_haddr - (nip - INSN_SIZE);

            if (target_off >= INT26_MIN && target_off <= INT26_MAX) {
                // Patch in a single b
                tmp_ctx.assembler->b((rel_off_26bit)target_off);
                macro$nops(*tmp_ctx.assembler, DIRECT_JMP_PATCH_INSN_COUNT - 1);
            } else {
                // Recalculate the offset to be relative to bla's new LR, not the relocation's position
                auto offs = calculate_pcrel_branch_patch_offsets(DIRECT_JMP_PATCH_INSN_COUNT, target_off);

                // Load the immediate offset
                macro$load_imm(*tmp_ctx.assembler, 0, offs.new_offset, llir::Register::Mask::Full64, true);

                // Fill in NOPs if required to pad immediate's offset from the branch
                macro$nops(*tmp_ctx.assembler, offs.middle_nops);

                // Branch to $jmp_direct_rel
                tmp_ctx.assembler->bla(ff_addresses.jmp_direct_rel);

                // Fill in NOPs at the end
                macro$nops(*tmp_ctx.assembler, offs.end_nops);
            }

            // Emit instructions to nip-4
            uint8_t *buffer_start = (uint8_t *)nip - INSN_SIZE;
            status_code res = tmp_ctx.stream->emit_all_to_buf(buffer_start, DIRECT_CALL_PATCH_INSN_COUNT*INSN_SIZE);
            if (res != status_code::SUCCESS) {
                pr_error("Failed to emit direct call patch: %s\n", status_code_str(res));
                return res;
            }

            // Rewind NIP to execute newly patched code
            nip = nip - INSN_SIZE;
            rctx.flush_icache = true;
            break;
        }

        default:
            // No patch necessary, just set NIP to the provided target and return
            nip = resolved_haddr;
            break;
    }

    return status_code::SUCCESS;
}

/**
 * Helper macros for using relocations with local labels
 */
#define RELOC_DECLARE_LABEL(name) \
    do ctx.stream->add_aux(true, relocation{1, relocation::declare_label{name}}); while (0)
#define RELOC_DECLARE_LABEL_AFTER(name) \
    do ctx.stream->add_aux(true, relocation{1, relocation::declare_label_after{name}}); while (0)
#define RELOC_FIXUP_LABEL(name, pos) \
    do ctx.stream->add_aux(true, relocation{1, relocation::imm_rel_label_fixup{name, LabelPosition::pos}}); while (0)

template <typename T>
void codegen_ppc64le<T>::dispatch(gen_context &ctx, const llir::Insn &insn) {
    ctx.local_branch_targets.insert({ insn.address, ctx.stream->size() });

    // If instruction has a condition attached to it, guard the translation with a branch
    switch (insn.condition) {
        case llir::Branch::Op::UNCONDITIONAL:
            break;
        case llir::Branch::Op::INVALID:
            ASSERT_NOT_REACHED();
        default:
        {
            // Evaluate condition
            uint8_t cr_field;
            BO bo;
            llir$branch$helper$evaluate_op(ctx, insn.condition, &cr_field, &bo);

            // Branch end of this insn's translation if condition is not true
            bo = llir$branch$helper$invert_bo(bo);
            ctx.assembler->bc(bo, cr_field, 0); RELOC_FIXUP_LABEL("dispatch_condition_false", AFTER);
        }
    }

    switch (insn.iclass()) {
        case llir::Insn::Class::ALU:
            switch (insn.alu().op) {
                case llir::Alu::Op::ADD:
                case llir::Alu::Op::AND:
                case llir::Alu::Op::IMUL:
                case llir::Alu::Op::MUL:
                case llir::Alu::Op::OR:
                case llir::Alu::Op::SAR:
                case llir::Alu::Op::SHL:
                case llir::Alu::Op::SHR:
                case llir::Alu::Op::SUB:
                case llir::Alu::Op::XOR:
                    llir$alu$2src_common(ctx, insn);
                    break;
                case llir::Alu::Op::LOAD_IMM:
                    llir$alu$load_imm(ctx, insn);
                    break;
                case llir::Alu::Op::MOVE_REG:
                    llir$alu$move_reg(ctx, insn);
                    break;
                case llir::Alu::Op::NOP:
                    ctx.assembler->nop();
                    break;
                case llir::Alu::Op::SETCC:
                    llir$alu$setcc(ctx, insn);
                    break;
                case llir::Alu::Op::SETFLAG:
                case llir::Alu::Op::CLRFLAG:
                    llir$alu$setclrflag(ctx, insn);
                    break;
                case llir::Alu::Op::X86_CPUID:
                    llir$alu$x86_cpuid(ctx, insn);
                    break;
                default:
                    pr_debug("Unimplemented ALU op: %s\n", llir::to_string(insn.alu()).c_str());
                    TODO();
            }
            break;

        case llir::Insn::Class::BRANCH:
            switch (insn.branch().op) {
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
            switch (insn.interrupt().op) {
                case llir::Interrupt::Op::SYSCALL:
                    llir$interrupt$syscall(ctx, insn);
                    break;

                case llir::Interrupt::Op::ILLEGAL:
                    ctx.assembler->invalid();
                    break;

                default:
                    TODO();
            }
            break;

        case llir::Insn::Class::LOADSTORE:
            switch (insn.loadstore().op) {
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

    RELOC_DECLARE_LABEL_AFTER("dispatch_condition_false");
}

template <typename T>
status_code codegen_ppc64le<T>::resolve_relocations(codegen_ppc64le<T>::gen_context &ctx) {
    instruction_stream_entry *insn; // Current instruction stream entry
    bool first_pass = true;         // Whether we're on the first pass or not
    size_t insn_i;                  // Index of current instruction
    std::unordered_map<std::string, std::vector<size_t>> labels;         // Map of label:insn_index for use in label resolution

    struct Deferral {
        size_t idx;     // Index of the deferred instruction in the stream
        size_t aux_idx; // Index of aux_data for deferred relocation
        instruction_stream_entry *entry;
    };
    std::vector<Deferral> deferred;

    // Helper to fix up absolute branches
    auto fixup_absolute_branch = [](auto &insn) {
        if (auto *aa = insn.template parameter_by_type<AA>()) {
            if (!*aa)
                return;

            pr_warn("Relocation requires changing branch from absolute to relative\n");
            *aa = (AA)false;
        }
    };

    // Helper to update an instruction's relative offset field with the provided offset
    auto update_relative_offset = [fixup_absolute_branch](auto &insn, int64_t target_off) -> status_code {
        if (auto *rel26 = insn.template parameter_by_type<rel_off_26bit>()) {
            // Instruction uses 26-bit relative offsets
            if (target_off < INT26_MIN || target_off > INT26_MAX)
                return status_code::BADBRANCH;

            *rel26 = (rel_off_26bit)target_off;
            fixup_absolute_branch(insn);
        } else if (auto *rel16 = insn.template parameter_by_type<rel_off_16bit>()) {
            // Instruction uses 16-bit relative offsets
            if (target_off < INT16_MIN || target_off > INT16_MAX)
                return status_code::BADBRANCH;

            *rel16 = (rel_off_16bit)target_off;
            fixup_absolute_branch(insn);
        } else {
            pr_debug("Unknown offset field in instruction marked with imm_rel_vaddr_fixup relocation!\n");
            return status_code::UNIMPL_INSN;
        }

        return status_code::SUCCESS;
    };

    // Visitor object for handling relocations
    auto relocation_visitor = Overloaded {
        [&](const relocation::imm_rel_vaddr_fixup &data) -> status_code {
            assert(first_pass); // Should never be called more than once
            /**
             * imm_rel_vaddr_fixup - Modify the instruction's rel_off* field to point to
             * the relative address corresponding to the provided absolute target virtual address.
             */
            auto target_index_it = ctx.local_branch_targets.find(data.vaddr);
            if (target_index_it == ctx.local_branch_targets.end()) {
                pr_error("Unable to resolve Immediate Branch to target 0x%lx\n", data.vaddr);
                return status_code::BADBRANCH;
            }
            size_t target_index = target_index_it->second;

            // Calculate the target's relative offset from us
            int64_t target_off = target_index*INSN_SIZE - insn_i*INSN_SIZE;

            // Update instruction's relative address field
            return update_relative_offset(*insn, target_off);
        },


        [&](const relocation::imm_rel_label_fixup &data) -> status_code {
            /**
             * imm_rel_label_fixup - Modify the instruction's rel_off* field to point to
             * the relative address corresponding to the provided label.
             */
            if (first_pass)
                // We only want to run on the second pass after all labels have been emitted
                return status_code::DEFER;

            auto &target_indexes = labels[data.label_name];

            std::optional<size_t> target_index;
            if (data.position == LabelPosition::BEFORE) {
                // Iterate backwards and find the first label index before our own
                auto target_index_it = std::find_if(target_indexes.rbegin(), target_indexes.rend(),
                                                    [&](const size_t &val) { return (val < insn_i); });
                if (target_index_it != target_indexes.rend())
                    target_index = *target_index_it;
            } else /* AFTER */ {
                // Iterate forwards and find the first label index after our own
                auto target_index_it = std::find_if(target_indexes.begin(), target_indexes.end(),
                                                    [&](const size_t &val) { return (val > insn_i); });
                if (target_index_it != target_indexes.end())
                    target_index = *target_index_it;
            }

            if (!target_index) {
                // Couldn't find suitable target label
                pr_debug("imm_rel_label_fixup: Unable to find target label %s\n", data.label_name.c_str());
                return status_code::BADBRANCH;
            }

            // Calculate the target's relative offset from us
            int64_t target_off = (*target_index)*INSN_SIZE - insn_i*INSN_SIZE;

            // Update instruction's relative address field
            return update_relative_offset(*insn, target_off);
        },

        [&](const relocation::declare_label &data) -> status_code {
            assert(first_pass);
            /**
             * declare_label - Declare a label that points to this instruction
             */
            labels[data.label_name].push_back(insn_i);
            return status_code::SUCCESS;
        },

        [&](const relocation::declare_label_after &data) -> status_code {
            assert(first_pass);
            /**
             * declare_label_after - Declare a label that points to the instruction *after* this one
             */
            labels[data.label_name].push_back(insn_i + 1);
            return status_code::SUCCESS;
        },

        [&](const relocation::imm_rel_direct_call &data) -> status_code {
            assert(first_pass);
            /**
             * imm_rel_direct_call - Emit a call to an immediate address
             */
            gen_context tmp_ctx(nullptr);

            // First, see if the target address' translation is in this code block
            auto target_index_it = ctx.local_branch_targets.find(data.vaddr);
            if (target_index_it != ctx.local_branch_targets.end()) {
                // Target is local, load its offset and emit a call to fixed_helper$call_direct_rel
                size_t target_index = target_index_it->second;
                int64_t target_off = target_index*INSN_SIZE - insn_i*INSN_SIZE;

                auto offs = calculate_pcrel_branch_patch_offsets(DIRECT_CALL_PATCH_INSN_COUNT, target_off);

                // Emit the patch
                macro$load_imm(*tmp_ctx.assembler, 0, offs.new_offset, llir::Register::Mask::Full64, true);

                // Fill in NOPs if required to pad immediate's offset from the branch
                macro$nops(*tmp_ctx.assembler, offs.middle_nops);

                // Emit branch to $call_direct_rel
                tmp_ctx.assembler->bla(ff_addresses.call_direct_rel);
            } else {
                // Target is unknown, it will have to be patched at run-time through a trap.
                // Emit a call to fixed_function$trap_patch_call, then store the unresolved
                // vaddr as a raw u64 in the instruction stream for the runtime to read.
                tmp_ctx.assembler->bla(ff_addresses.trap_patch_call);
                tmp_ctx.assembler->u32(data.vaddr & 0xFFFFFFFF);
                tmp_ctx.assembler->u32((uint32_t)((data.vaddr >> 32) & 0xFFFFFFFF));
            }

            // Make sure we didn't overshoot the allocated patch buffer
            assert(tmp_ctx.stream->size() <= DIRECT_CALL_PATCH_INSN_COUNT);

            // Move patched instructions into the main instruction stream
            size_t new_stream_size = tmp_ctx.stream->size();
            for (size_t i = 0; i < new_stream_size; i++) {
                (*ctx.stream)[insn_i + i].replace_with(std::move((*tmp_ctx.stream)[i]));
            }

            return status_code::SUCCESS;
        },

        [&](const relocation::imm_rel_direct_jmp &data) -> status_code {
            assert(first_pass);
            /**
             * imm_rel_direct_jmp - Emit a jump to an immediate address
             */
            gen_context tmp_ctx(nullptr);

            // First, see if the target address' translation is in this code block
            auto target_index_it = ctx.local_branch_targets.find(data.vaddr);
            if (target_index_it != ctx.local_branch_targets.end()) {
                size_t target_index = target_index_it->second;
                int64_t target_off = target_index*INSN_SIZE - insn_i*INSN_SIZE;
                assert(target_off >= INT26_MIN);
                assert(target_off <= INT26_MAX);

                // Emit a single b instruction
                tmp_ctx.assembler->b((rel_off_26bit)target_off);

                // FIXME: optimize away the NOPs after this insn
            } else {
                // Target is unknown, it will have to be patched at run-time.
                tmp_ctx.assembler->bla(ff_addresses.trap_patch_jump);
                tmp_ctx.assembler->u32(data.vaddr & 0xFFFFFFFF);
                tmp_ctx.assembler->u32((uint32_t)((data.vaddr >> 32) & 0xFFFFFFFF));
            }

            // Make sure we didn't overshoot the allocated patch buffer
            assert(tmp_ctx.stream->size() <= DIRECT_JMP_PATCH_INSN_COUNT);

            // Move patched instructions into the main instruction stream
            size_t new_stream_size = tmp_ctx.stream->size();
            for (size_t i = 0; i < new_stream_size; i++) {
                (*ctx.stream)[insn_i + i].replace_with(std::move((*tmp_ctx.stream)[i]));
            }

            return status_code::SUCCESS;
        }
    };

    // Walk the instruction stream and look for relocations
    for (size_t i = 0; i < ctx.stream->size(); i++) {
        insn = &(*ctx.stream)[i];
        insn_i = i;

        for (size_t aux_i = 0; aux_i < insn->aux_data().size(); aux_i++) {
            auto &aux = insn->aux_data()[aux_i];
            if (!aux->relocation)
                continue;

            // Attempt to resolve this relocation
            auto res = std::visit(relocation_visitor, aux->relocation->data);
            if (res == status_code::DEFER) {
                // Try again after other relocations have been resovled
                deferred.push_back({insn_i, aux_i, insn});
            } else if (res != status_code::SUCCESS) {
                // Failure - bail out
                return res;
            }
        }
    }

    // If there are any deferred relocations, do a second pass
    first_pass = false;
    for (size_t i = 0; i < deferred.size(); i++) {
        auto &deferral = deferred[i];
        insn_i = deferral.idx;
        insn = deferral.entry;

        // Attempt again to resolve this relocation
        auto res = std::visit(relocation_visitor, insn->aux_data()[deferral.aux_idx]->relocation->data);

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
                                                               const llir::Operand &op, gpr_t target,
                                                               llir::Extension extension) {
    switch (op.type()) {
        case llir::Operand::Type::REG:
        {
            // Operand is in a register, move it to the target reg and mask it
            auto gpr = ctx.reg_allocator().get_fixed_gpr(op.reg());
            switch (extension) {
                case llir::Extension::ZERO:
                    macro$move_register_masked(*ctx.assembler, target, gpr.gpr(), op.reg().mask,
                                               llir::Register::Mask::Full64, true, false);
                    break;

                case llir::Extension::SIGN:
                    // Sign extend the operand - necessary for some ALU operations to produce a valid result on
                    // operands that are less than 64-bits.
                    switch (op.reg().mask) {
                        case llir::Register::Mask::Full64:
                            ctx.assembler->mr(target, gpr.gpr());
                            break;
                        case llir::Register::Mask::Low32:
                            ctx.assembler->extsw(target, gpr.gpr());
                            break;
                        case llir::Register::Mask::LowLow16:
                            ctx.assembler->extsh(target, gpr.gpr());
                            break;
                        case llir::Register::Mask::LowLowLow8:
                            ctx.assembler->extsb(target, gpr.gpr());
                            break;
                        case llir::Register::Mask::LowLowHigh8:
                            ctx.assembler->rldicl(target, gpr.gpr(), 64-8, 64-8, false);
                            ctx.assembler->extsb(target, target);
                            break;
                        default:
                            ASSERT_NOT_REACHED();
                    }
                    break;

                case llir::Extension::NONE:
                    ASSERT_NOT_REACHED();
            }
            break;
        }

        case llir::Operand::Type::IMM:
        {
            // Operand is an immediate, load it into the target reg.
            //
            // If sign extension was requested, treat the destination width as 64-bit unconditionally so
            // that macro$load_imm will extend the sign across the entire register - otherwise use the
            // operation's width.
            auto width = extension == llir::Extension::SIGN ? llir::Operand::Width::_64BIT : op.width;
            macro$load_imm(*ctx.assembler, target, op.imm(), llir$alu$helper$mask_from_width(width), true);
            break;
        }

        case llir::Operand::Type::MEM:
            // Operand is in memory, load it into the target reg
            macro$loadstore(ctx, target, op, llir::LoadStore::Op::LOAD, llir$alu$helper$mask_from_width(op.width), true,
                            insn, extension);
            break;

        default:
            TODO();
    }
}

template <typename T>
void codegen_ppc64le<T>::llir$alu$helper$finalize_op(gen_context &ctx, const llir::Insn &insn, LastFlagOp op) {
    if (insn.dest_cnt) {
        auto res_mask = llir$alu$helper$mask_from_width(insn.dest[0].width);

        switch(insn.dest[0].type()) {
            case llir::Operand::Type::REG:
            {
                // Copy result to destination register
                auto dest = ctx.reg_allocator().get_fixed_gpr(insn.dest[0].reg());

                macro$move_register_masked(*ctx.assembler, dest.gpr(), GPR_FIXED_FLAG_RES, res_mask,
                                           insn.dest[0].reg().mask, insn.dest[0].reg().zero_others, false);
                break;
            }

            case llir::Operand::Type::MEM:
                // Store result to memory
                macro$loadstore(ctx, GPR_FIXED_FLAG_RES, insn.dest[0], llir::LoadStore::Op::STORE, res_mask, true, insn);
                break;

            default:
                TODO();
        }

    }

    auto mask = llir$alu$helper$mask_from_width(insn.src[0].width);
    bool needs_calculated_rc0 = contains_any(insn.alu().flags_modified, llir$alu$all_rc0_flags)
                                && !contains_all(insn.alu().flags_cleared, llir$alu$all_rc0_flags)
                                && !contains_all(insn.alu().flags_undefined, llir$alu$all_rc0_flags);
    if (needs_calculated_rc0 && mask != llir::Register::Mask::Full64) {
        // If the instruction modifies rc0 flags and the mask is < 64, we need to generate the cr0 flags
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


    if (!insn.alu().modifies_flags) {
        // Instruction doesn't modify flags, nothing left to do
        return;
    }

    // Record flag operation type in GPR_FIXED_FLAG_OP_TYPE if we need lazy evaluation.
    // lazy evaluation is necessary when a lazy flag is modified but not explicitly cleared.
    auto modified_but_not_cleared = insn.alu().flags_modified.difference(insn.alu().flags_cleared);
    if (contains_any(llir$alu$all_lazy_flags, modified_but_not_cleared)) {
        uint32_t flag_data = build_flag_op_data(op, mask);
        macro$load_imm(*ctx.assembler, GPR_FIXED_FLAG_OP_TYPE, flag_data, llir::Register::Mask::Low32, true);
    }
    assert(!contains_any(llir$alu$all_rc0_flags, insn.alu().flags_cleared)); // FIXME: support clearing rc0 flags

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

    auto alu_flag_to_lazy = [](llir::Alu::Flag f) -> std::optional<uint8_t> {
        switch (f) {
            case llir::Alu::Flag::CARRY:
                return CR_LAZY_FIELD_CARRY;
            case llir::Alu::Flag::OVERFLOW:
                return CR_LAZYVALID_OVERFLOW;
            default:
                return std::nullopt;
        }
    };

    StaticVector<uint8_t, 4> lazyvalid_to_clear;
    StaticVector<uint8_t, 4> lazyvalid_to_set;
    StaticVector<uint8_t, 4> lazy_to_clear;

    // Update lazy CR state per modified flag
    for (auto flag : insn.alu().flags_modified) {
        auto lazyvalid_field = alu_flag_to_lazyvalid(flag);
        if (!lazyvalid_field)
            continue;
        if (contains(insn.alu().flags_undefined, flag))
            continue;

        if (contains(insn.alu().flags_cleared, flag)) {
            // Modified and cleared - valid, unset
            lazyvalid_to_set.push_back(*lazyvalid_field);
            lazy_to_clear.push_back(*alu_flag_to_lazy(flag));
        } else {
            // Modified but not cleared - invalid
            lazyvalid_to_clear.push_back(*lazyvalid_field);
        }
    };


    // FIXME: This is pretty inefficient for most cases
    // Update CR_LAZYVALID
    if (lazyvalid_to_clear.size() && !lazyvalid_to_set.size()) {
        // Optimization: zero out all LAZYVALID fields
        ctx.assembler->mcrf(CR_LAZYVALID, CR_ZEROS);
    } else {
        // Loop through all bits and clear/set appropriately
        for (auto field : lazyvalid_to_clear)
            ctx.assembler->crclr(field);
        for (auto field : lazyvalid_to_set)
            ctx.assembler->crset(field);
    }

    // Update CR_LAZY
    for (auto field : lazy_to_clear)
        ctx.assembler->crclr(field);
}

template <typename T>
llir::Alu::FlagArr codegen_ppc64le<T>::llir$alu$helper$preserve_flags(gen_context &ctx, const llir::Insn &insn) {
    if (!insn.alu().modifies_flags)
        return {};

    // If this operation preserves any flags generated by Rc=1, we need to back them up and restore at the end
    llir::Alu::FlagArr preserved;
    size_t preserved_i = 0;

    for (auto flag : llir$alu$all_rc0_flags) {
        if (!contains(insn.alu().flags_modified, flag) && !contains(insn.alu().flags_undefined, flag)) {
            // Flag wasn't modified and isn't undefined - we need to preserve it
            preserved.push_back(flag);
        }
    };

    // Move cr0 to CR_SCRATCH, so $restore_flags can restore them later
    if (preserved_i)
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

    for (auto flag : flags) {
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
    };
}

template <typename T>
size_t codegen_ppc64le<T>::llir$alu$helper$load_imm_insn_count(int64_t val) {
    gen_context tmp(nullptr);
    tmp.assembler->set_quiet(true);
    macro$load_imm(*tmp.assembler, 0, val, llir::Register::Mask::Full64, true);
    return tmp.stream->size();
}

template <typename T>
LastFlagOp codegen_ppc64le<T>::llir$alu$helper$insn_to_lastflagop(const llir::Insn &insn) {
    switch (insn.alu().op) {
        case llir::Alu::Op::ADD:
            return LastFlagOp::ADD;
        case llir::Alu::Op::IMUL:
            return LastFlagOp::IMUL;
        case llir::Alu::Op::MUL:
            return LastFlagOp::MUL;
        case llir::Alu::Op::SUB:
            return LastFlagOp::SUB;
        case llir::Alu::Op::SHL:
            return LastFlagOp::SHL;
        case llir::Alu::Op::SHR:
            return LastFlagOp::SHR;
        case llir::Alu::Op::SAR:
            return LastFlagOp::SAR;
        case llir::Alu::Op::AND:
        case llir::Alu::Op::OR:
        case llir::Alu::Op::XOR:
            return LastFlagOp::INVALID;
        default:
            TODO();
    }
}

template <typename T>
void codegen_ppc64le<T>::llir$alu$load_imm(gen_context &ctx, const llir::Insn &insn) {
    pr_debug("alu$load_imm\n");
    assert(insn.dest_cnt == 1);
    assert(insn.dest[0].type() == llir::Operand::Type::REG);
    assert(insn.src_cnt == 1);
    assert(insn.src[0].type() == llir::Operand::Type::IMM);

    auto rt = ctx.reg_allocator().get_fixed_gpr(insn.dest[0].reg());

    macro$load_imm(*ctx.assembler, rt.gpr(), insn.src[0].imm(), insn.dest[0].reg().mask, insn.dest[0].reg().zero_others);
}

template <typename T>
void codegen_ppc64le<T>::llir$alu$2src_common(gen_context &ctx, const llir::Insn &insn) {
    pr_debug("alu$2src\n");
    assert(insn.src_cnt == 2);
    assert(insn.alu().extension == llir::Extension::NONE);
    auto width = insn.src[0].width;

    // Preserve flags
    llir::Alu::FlagArr preserved;
    if (insn.alu().modifies_flags)
        preserved = llir$alu$helper$preserve_flags(ctx, insn);

    bool modify_cr = (insn.alu().modifies_flags && width == llir::Operand::Width::_64BIT);
    switch (insn.alu().op) {
        case llir::Alu::Op::ADD:
            llir$alu$helper$load_operand_into_gpr(ctx, insn, insn.src[0], GPR_FIXED_FLAG_OP1);
            llir$alu$helper$load_operand_into_gpr(ctx, insn, insn.src[1], GPR_FIXED_FLAG_OP2);
            ctx.assembler->add(GPR_FIXED_FLAG_RES, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2, modify_cr);
            break;

        case llir::Alu::Op::AND:
            llir$alu$helper$load_operand_into_gpr(ctx, insn, insn.src[0], GPR_FIXED_FLAG_OP1);
            llir$alu$helper$load_operand_into_gpr(ctx, insn, insn.src[1], GPR_FIXED_FLAG_OP2);
            ctx.assembler->_and(GPR_FIXED_FLAG_RES, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2, modify_cr);
            break;

        case llir::Alu::Op::IMUL:
        {
            // Operands must be sign extended
            llir$alu$helper$load_operand_into_gpr(ctx, insn, insn.src[0], GPR_FIXED_FLAG_OP1, llir::Extension::SIGN);
            llir$alu$helper$load_operand_into_gpr(ctx, insn, insn.src[1], GPR_FIXED_FLAG_OP2, llir::Extension::SIGN);

            typename register_allocator<T>::AllocatedGprT high_dest;
            if (insn.dest_cnt == 2) {
                // If insn has second destination, store high bits of result in it.
                // Must be a register.
                high_dest = ctx.reg_allocator().get_fixed_gpr(insn.dest[1].reg());
                assert(insn.dest[1].reg().mask != llir::Register::Mask::LowLowHigh8);
            }

            switch (width) {
                case llir::Operand::Width::_64BIT:
                    ctx.assembler->mulld(GPR_FIXED_FLAG_RES, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2, false, true);
                    if (high_dest)
                        ctx.assembler->mulhd(high_dest.gpr(), GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2);
                    break;
                case llir::Operand::Width::_32BIT:
                    ctx.assembler->mullw(GPR_FIXED_FLAG_RES, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2, false, true);
                    if (high_dest)
                        ctx.assembler->mulhw(high_dest.gpr(), GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2);
                    break;
                case llir::Operand::Width::_16BIT:
                    ctx.assembler->mullw(GPR_FIXED_FLAG_RES, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2, false, false);
                    if (high_dest) {
                        // Move top GPR_FIXED_FLAG_RES[31:16] to high_dest[15:0]
                        assert(!insn.dest[1].reg().zero_others);
                        ctx.assembler->rlwimi(high_dest.gpr(), GPR_FIXED_FLAG_RES, 32-16, 32-16, 31);
                    }
                    break;
                case llir::Operand::Width::_8BIT:
                    ctx.assembler->mullw(GPR_FIXED_FLAG_RES, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2, false, false);
                    if (high_dest) {
                        // Move top GPR_FIXED_FLAG_RES[15:8] to high_dest[7:0]
                        assert(!insn.dest[1].reg().zero_others);
                        ctx.assembler->rlwimi(high_dest.gpr(), GPR_FIXED_FLAG_RES, 32-8, 32-8, 31);
                    }
                    break;
                case llir::Operand::Width::INVALID:
                    ASSERT_NOT_REACHED();
            }
            break;
        }

        case llir::Alu::Op::MUL:
        {
            llir$alu$helper$load_operand_into_gpr(ctx, insn, insn.src[0], GPR_FIXED_FLAG_OP1);
            llir$alu$helper$load_operand_into_gpr(ctx, insn, insn.src[1], GPR_FIXED_FLAG_OP2);

            // insn has second destination, store high bits of result in it (must be a register)
            typename register_allocator<T>::AllocatedGprT high_dest;
            if (insn.dest_cnt == 2) {
                // If insn has second destination, store high bits of result in it.
                // Must be a register.
                high_dest = ctx.reg_allocator().get_fixed_gpr(insn.dest[1].reg());
                assert(insn.dest[1].reg().mask != llir::Register::Mask::LowLowHigh8);
            }

            switch (width) {
                case llir::Operand::Width::_64BIT:
                    ctx.assembler->mulld(GPR_FIXED_FLAG_RES, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2, false, false);
                    ctx.assembler->mulhdu(high_dest.gpr(), GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2);
                    break;
                case llir::Operand::Width::_32BIT:
                    ctx.assembler->mulld(GPR_FIXED_FLAG_RES, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2, false, false);
                    if (high_dest) {
                        // Move top GPR_FIXED_FLAG_RES[63:32] to high_dest[31:0]
                        assert(insn.dest[1].reg().zero_others);
                        ctx.assembler->rldicl(high_dest.gpr(), GPR_FIXED_FLAG_RES, 64-32, 64-32, false);
                    }
                    break;
                case llir::Operand::Width::_16BIT:
                    ctx.assembler->mullw(GPR_FIXED_FLAG_RES, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2, false, false);
                    if (high_dest) {
                        // Move top GPR_FIXED_FLAG_RES[31:16] to high_dest[15:0]
                        assert(!insn.dest[1].reg().zero_others);
                        ctx.assembler->rlwimi(high_dest.gpr(), GPR_FIXED_FLAG_RES, 32-16, 32-16, 31);
                    }
                    break;
                case llir::Operand::Width::_8BIT:
                    ctx.assembler->mullw(GPR_FIXED_FLAG_RES, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2, false, false);
                    if (high_dest) {
                        // Move top GPR_FIXED_FLAG_RES[15:8] to high_dest[7:0]
                        assert(!insn.dest[1].reg().zero_others);
                        ctx.assembler->rlwimi(high_dest.gpr(), GPR_FIXED_FLAG_RES, 32-8, 32-8, 31);
                    }
                    break;
                case llir::Operand::Width::INVALID:
                    ASSERT_NOT_REACHED();
            }
            break;
        }

        case llir::Alu::Op::OR:
            llir$alu$helper$load_operand_into_gpr(ctx, insn, insn.src[0], GPR_FIXED_FLAG_OP1);
            llir$alu$helper$load_operand_into_gpr(ctx, insn, insn.src[1], GPR_FIXED_FLAG_OP2);
            ctx.assembler->_or(GPR_FIXED_FLAG_RES, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2, modify_cr);
            break;

        case llir::Alu::Op::SAR:
            llir$alu$helper$load_operand_into_gpr(ctx, insn, insn.src[0], GPR_FIXED_FLAG_OP1, llir::Extension::SIGN);
            llir$alu$helper$load_operand_into_gpr(ctx, insn, insn.src[1], GPR_FIXED_FLAG_OP2);
            ctx.assembler->srad(GPR_FIXED_FLAG_RES, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2);
            break;

        case llir::Alu::Op::SHL:
            llir$alu$helper$load_operand_into_gpr(ctx, insn, insn.src[0], GPR_FIXED_FLAG_OP1);
            llir$alu$helper$load_operand_into_gpr(ctx, insn, insn.src[1], GPR_FIXED_FLAG_OP2);
            ctx.assembler->sld(GPR_FIXED_FLAG_RES, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2);
            break;

        case llir::Alu::Op::SHR:
            llir$alu$helper$load_operand_into_gpr(ctx, insn, insn.src[0], GPR_FIXED_FLAG_OP1);
            llir$alu$helper$load_operand_into_gpr(ctx, insn, insn.src[1], GPR_FIXED_FLAG_OP2);
            ctx.assembler->srd(GPR_FIXED_FLAG_RES, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2);
            break;

        case llir::Alu::Op::SUB:
            llir$alu$helper$load_operand_into_gpr(ctx, insn, insn.src[0], GPR_FIXED_FLAG_OP1);
            llir$alu$helper$load_operand_into_gpr(ctx, insn, insn.src[1], GPR_FIXED_FLAG_OP2);
            ctx.assembler->sub(GPR_FIXED_FLAG_RES, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2, false, modify_cr);
            break;

        case llir::Alu::Op::XOR:
            llir$alu$helper$load_operand_into_gpr(ctx, insn, insn.src[0], GPR_FIXED_FLAG_OP1);
            llir$alu$helper$load_operand_into_gpr(ctx, insn, insn.src[1], GPR_FIXED_FLAG_OP2);
            ctx.assembler->_xor(GPR_FIXED_FLAG_RES, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2, modify_cr);
            break;

        default:
            TODO();
    }

    // Restore flags
    if (insn.alu().modifies_flags)
        llir$alu$helper$restore_flags(ctx, preserved);

    // Finalize operation
    llir$alu$helper$finalize_op(ctx, insn, llir$alu$helper$insn_to_lastflagop(insn));
}

template <typename T>
void codegen_ppc64le<T>::llir$alu$move_reg(gen_context &ctx, const llir::Insn &insn) {
    pr_debug("alu$move_reg\n");
    assert(insn.src_cnt == 1);
    assert(insn.dest_cnt == 1);
    assert(!insn.alu().modifies_flags);

    auto src = insn.src[0].reg();
    auto dest = insn.dest[0].reg();
    auto src_reg = ctx.reg_allocator().get_fixed_gpr(src);
    auto dest_reg = ctx.reg_allocator().get_fixed_gpr(dest);

    switch (insn.alu().extension) {
        case llir::Extension::NONE:
        case llir::Extension::ZERO:
            macro$move_register_masked(*ctx.assembler, dest_reg.gpr(), src_reg.gpr(), insn.src[0].reg().mask,
                                       insn.dest[0].reg().mask, insn.dest[0].reg().zero_others, false);
            break;
        case llir::Extension::SIGN:
            typename register_allocator<T>::AllocatedGprT ext_dest_reg;
            if (dest.mask == llir::Register::Mask::Full64)
                // Store result directly into dest reg
                ext_dest_reg = std::move(dest_reg);
            else
                // Store result into temporary register and move after
                ext_dest_reg = ctx.reg_allocator().allocate_gpr();

            switch (src.mask) {
                case llir::Register::Mask::Low32:
                    ctx.assembler->extsw(ext_dest_reg.gpr(), src_reg.gpr());
                    break;
                case llir::Register::Mask::LowLow16:
                    ctx.assembler->extsh(ext_dest_reg.gpr(), src_reg.gpr());
                    break;
                case llir::Register::Mask::LowLowLow8:
                    ctx.assembler->extsb(ext_dest_reg.gpr(), src_reg.gpr());
                    break;
                case llir::Register::Mask::LowLowHigh8:
                    ctx.assembler->srdi(ext_dest_reg.gpr(), src_reg.gpr(), 8);
                    ctx.assembler->extsb(ext_dest_reg.gpr(), ext_dest_reg.gpr());
                    break;
                case llir::Register::Mask::Full64:
                case llir::Register::Mask::Special:
                    ASSERT_NOT_REACHED();
            }

            // Move the result into the destination register with mask if necessary
            if (dest.mask != llir::Register::Mask::Full64)
                macro$move_register_masked(*ctx.assembler, dest_reg.gpr(), ext_dest_reg.gpr(),
                                           llir$alu$helper$target_mask(src.mask), dest.mask, dest.zero_others,
                                           false, llir::Extension::NONE);

            break;
    }
}

template <typename T>
void codegen_ppc64le<T>::llir$alu$setcc(gen_context &ctx, const llir::Insn &insn) {
    pr_debug("alu$setcc\n");
    assert(insn.dest_cnt == 1);
    assert(insn.src_cnt == 1);

    // Evaluate the condition and get the relevant CR field and BO type
    uint8_t cr_field;
    BO bo;
    llir$branch$helper$evaluate_op(ctx, insn.src[0].branchop(), &cr_field, &bo);

    // Branch on the condition and set the result to a temporary register
    // FIXME: investigate whether it's faster to use isel here?
    auto tmp = ctx.reg_allocator().allocate_gpr();
    ctx.assembler->bc(bo, cr_field, 0); RELOC_FIXUP_LABEL("setcc_true", AFTER);
    /* fallthrough to false */

    { // condition is false
        ctx.assembler->li(tmp.gpr(), 0);
        ctx.assembler->b(0); RELOC_FIXUP_LABEL("setcc_common", AFTER);
    }

    { // condition is true
        ctx.assembler->li(tmp.gpr(), 1); RELOC_DECLARE_LABEL("setcc_true");
        ctx.assembler->nop();
        /* fallthrough to common */
    }
    RELOC_DECLARE_LABEL_AFTER("setcc_common");

    // Move from tmp register to destination
    switch(insn.dest[0].type()) {
        case llir::Operand::Type::REG:
        {
            // Copy result to destination register
            auto dest = ctx.reg_allocator().get_fixed_gpr(insn.dest[0].reg());

            macro$move_register_masked(*ctx.assembler, dest.gpr(), tmp.gpr(), insn.dest[0].reg().mask,
                                       insn.dest[0].reg().mask, insn.dest[0].reg().zero_others, false);
            break;
        }

        case llir::Operand::Type::MEM:
            // Store result to memory
            macro$loadstore(ctx, tmp.gpr(), insn.dest[0], llir::LoadStore::Op::STORE,
                            llir$alu$helper$mask_from_width(insn.dest[0].width), true, insn);
            break;

        default:
            ASSERT_NOT_REACHED();
    }
}

template <typename T>
void codegen_ppc64le<T>::llir$alu$setclrflag(gen_context &ctx, const llir::Insn &insn) {
    pr_debug("alu$setclrflag\n");

    auto setclr = [&](uint8_t cr_field) {
        switch (insn.alu().op) {
            case llir::Alu::Op::SETFLAG:
                ctx.assembler->crset(cr_field);
                break;
            case llir::Alu::Op::CLRFLAG:
                ctx.assembler->crclr(cr_field);
                break;
            default: ASSERT_NOT_REACHED();
        }
    };

    llir::Alu::Flag modified = insn.alu().flags_modified[0];
    switch (modified) {
        case llir::Alu::Flag::CARRY:
            ctx.assembler->crset(CR_LAZY_FIELD_CARRY);
            setclr(CR_LAZY_FIELD_CARRY);
            break;
        case llir::Alu::Flag::OVERFLOW:
            ctx.assembler->crset(CR_LAZY_FIELD_OVERFLOW);
            setclr(CR_LAZY_FIELD_OVERFLOW);
            break;
        case llir::Alu::Flag::SIGN:
            setclr(0*4 + assembler::CR_LT);
            break;
        case llir::Alu::Flag::ZERO:
            setclr(0*4 + assembler::CR_EQ);
            break;
        case llir::Alu::Flag::DIRECTION:
            setclr(CR_MISCFLAGS_FIELD_DIRECTION);
            break;
        case llir::Alu::Flag::PARITY:
        case llir::Alu::Flag::AUXILIARY_CARRY:
            TODO();
        case llir::Alu::Flag::COUNT:
        case llir::Alu::Flag::INVALID:
            ASSERT_NOT_REACHED();
    }
}

template <typename T>
void codegen_ppc64le<T>::llir$alu$x86_cpuid(gen_context &ctx, [[maybe_unused]] const llir::Insn &insn) {
    pr_debug("alu$x86_cpuid\n");
    ctx.assembler->bla(ff_addresses.cpuid);
}

/**
 * Return target virtual address for given branch
 */
template <typename T>
uint64_t codegen_ppc64le<T>::resolve_branch_target(const llir::Insn &insn) {
    uint64_t res;
    switch (insn.branch().target) {
        case llir::Branch::Target::RELATIVE:
            res = insn.address + (uint64_t)insn.src[0].imm();
            break;
        case llir::Branch::Target::ABSOLUTE:
            res = (uint64_t)insn.src[0].imm();
            break;
        default:
            TODO();
    }

    pr_debug("Resolved LLINSN branch target to 0x%lx: %s\n", res, llir::to_string(insn).c_str());
    return res;
}

template <typename T>
void codegen_ppc64le<T>::llir$branch$helper$evaluate_op(gen_context &ctx, llir::Branch::Op op, uint8_t *cr_field_out, BO *bo_out) {
    uint8_t cr_field;
    BO bo;

    switch (op) {
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

    if (cr_field_out)
        *cr_field_out = cr_field;
    if (bo_out)
        *bo_out = bo;
}

template <typename T>
void codegen_ppc64le<T>::llir$branch$unconditional(gen_context &ctx, const llir::Insn &insn) {
    pr_debug("branch$unconditional\n");
    assert(insn.src_cnt == 1);

    if (!insn.branch().linkage) {
        // Unconditional branch without linkage, i.e. JMP
        assert(insn.dest_cnt == 0);
        switch (insn.src[0].type()) {
            case llir::Operand::Type::IMM:
            {
                // Emit a relocation to directly branch to the correct offset. We don't need any fixed_helper
                // calls because the target is known (direct) AND we don't need to touch the call cache.
                //
                // In the case of 26-bit relative targets, this will resolve to 1 instruction and 3 NOPs.
                // Otherwise it will resolve to a load_imm, mtctr, bctr.
                uint64_t target = resolve_branch_target(insn);
                macro$nop$relocation(ctx, DIRECT_JMP_PATCH_INSN_COUNT,
                                     relocation{DIRECT_JMP_PATCH_INSN_COUNT, relocation::imm_rel_direct_jmp{target}});
                break;
            }

            case llir::Operand::Type::MEM:
                // Load operand into r0 and call fixed_helper$indirect_jmp
                macro$loadstore(ctx, 0, insn.src[0], llir::LoadStore::Op::LOAD,
                                llir$alu$helper$mask_from_width(insn.src[0].width), true, insn);
                ctx.assembler->bla(ff_addresses.indirect_jmp);
                break;

            case llir::Operand::Type::REG:
            {
                // Load operand into r0 and call fixed_helper$indirect_jmp
                auto dest_reg = ctx.reg_allocator().get_fixed_gpr(insn.src[0].reg());
                macro$move_register_masked(*ctx.assembler, 0, dest_reg.gpr(), llir::Register::Mask::Full64,
                                           insn.src[0].reg().mask, true, false);
                ctx.assembler->bla(ff_addresses.indirect_jmp);
                break;
            }

            case llir::Operand::Type::BRANCHOP: ASSERT_NOT_REACHED();
        }
    } else {
        // Unconditional branch with linkage, i.e. CALL
        assert(insn.dest_cnt == 1);
        assert(insn.dest[0].type() == llir::Operand::Type::MEM);

        switch (insn.src[0].type()) {
            case llir::Operand::Type::IMM:
            {
                // Write return vaddr to memory operand
                auto ret_vaddr_reg = ctx.reg_allocator().allocate_gpr();
                uint64_t ret_vaddr = insn.address + insn.size;
                macro$load_imm(*ctx.assembler, ret_vaddr_reg.gpr(), ret_vaddr, llir::Register::Mask::Full64, true);
                macro$loadstore(ctx, ret_vaddr_reg.gpr(), insn.dest[0], llir::LoadStore::Op::STORE,
                                llir$alu$helper$mask_from_width(insn.dest[0].width), true, insn);

                // Emit a relocation that will load the target host address into 0 and try to bla to
                // fixed_helper$call_direct_pcrel
                //
                // We bother with a relocation here because if the target has a locally-known mapping,
                // we can use $call_direct_pcrel instead of $call which avoids the run-time vaddr lookup, so
                // it should be much faster.
                //
                // In the future when we could add support for patching $call callers to $call_direct after the
                // first call once the vaddr mapping is known which would probably make this useless.
                uint64_t target = resolve_branch_target(insn);
                macro$nop$relocation(ctx, DIRECT_CALL_PATCH_INSN_COUNT,
                                     relocation{DIRECT_CALL_PATCH_INSN_COUNT, relocation::imm_rel_direct_call{target}});
                break;
            }

            case llir::Operand::Type::REG:
            {
                // Load destination vaddr in r0
                auto dest_reg = ctx.reg_allocator().get_fixed_gpr(insn.src[0].reg());
                macro$move_register_masked(*ctx.assembler, 0, dest_reg.gpr(), llir::Register::Mask::Full64,
                                           insn.src[0].reg().mask, true, false);

                // Write return vaddr to memory operand
                auto ret_vaddr_reg = ctx.reg_allocator().allocate_gpr();
                uint64_t ret_vaddr = insn.address + insn.size;
                macro$load_imm(*ctx.assembler, ret_vaddr_reg.gpr(), ret_vaddr, llir::Register::Mask::Full64, true);
                macro$loadstore(ctx, ret_vaddr_reg.gpr(), insn.dest[0], llir::LoadStore::Op::STORE,
                                llir$alu$helper$mask_from_width(insn.dest[0].width), true, insn);

                // Call fixed_helper$call
                ctx.assembler->bla(ff_addresses.call);
                break;
            }

            case llir::Operand::Type::MEM:
            {
                // Load destination vaddr in r0
                macro$loadstore(ctx, 0, insn.src[0], llir::LoadStore::Op::LOAD, llir::Register::Mask::Full64, true, insn);

                // Write return vaddr to memory operand
                auto ret_vaddr_reg = ctx.reg_allocator().allocate_gpr();
                uint64_t ret_vaddr = insn.address + insn.size;
                macro$load_imm(*ctx.assembler, ret_vaddr_reg.gpr(), ret_vaddr, llir::Register::Mask::Full64, true);
                macro$loadstore(ctx, ret_vaddr_reg.gpr(), insn.dest[0], llir::LoadStore::Op::STORE,
                                llir$alu$helper$mask_from_width(insn.dest[0].width), true, insn);

                // Call fixed_helper$call
                ctx.assembler->bla(ff_addresses.call);
                break;
            }

            case llir::Operand::Type::BRANCHOP: ASSERT_NOT_REACHED();
        }
    }
}

template <typename T>
BO codegen_ppc64le<T>::llir$branch$helper$invert_bo(BO bo) {
    switch (bo) {
        case BO::ALWAYS:
            return BO::ALWAYS;
        case BO::FIELD_CLR:
            return BO::FIELD_SET;
        case BO::FIELD_SET:
            return BO::FIELD_CLR;
    }
    ASSERT_NOT_REACHED();
}

template <typename T>
void codegen_ppc64le<T>::llir$branch$conditional(codegen_ppc64le::gen_context &ctx, const llir::Insn &insn) {
    pr_debug("branch$conditional\n");
    assert(!insn.branch().linkage);
    assert(insn.dest_cnt == 0);
    assert(insn.src_cnt == 1);

    //uint64_t target = resolve_branch_target(insn);
    uint8_t cr_field;
    BO bo;
    llir$branch$helper$evaluate_op(ctx, insn.branch().op, &cr_field, &bo);

    // Now that the condition fields have been determined and lazily evaluated (if necessary),
    // it's time to emit the branch. To make it easier to handle all operand types and reduce
    // the number of required runtime patch and relocation types, we'll re-use the unconditional
    // branch code to branch to the actual target, but we'll guard it with a local conditional
    // branch.
    //
    // For example, a `beq TARGET` will get compiled to:
    //   bne skip
    //   b TARGET
    //   skip:
    //
    // This way the `b TARGET` can use the same relocations and run-time patches without caring
    // about the condition code.
    //
    // FIXME: In the future we should optimize for cases where the target is an immediate, local,
    // and 26-bit rel addressable.
    ctx.assembler->bc(llir$branch$helper$invert_bo(bo), cr_field, 0);
    RELOC_FIXUP_LABEL("branch_conditional_skip", AFTER);
    llir$branch$unconditional(ctx, insn);
    RELOC_DECLARE_LABEL_AFTER("branch_conditional_skip");
}

template <typename T>
void codegen_ppc64le<T>::llir$interrupt$syscall(gen_context &ctx, const llir::Insn &insn) {
    pr_debug("interrupt$syscall\n");
    assert(insn.dest_cnt == 0 && insn.src_cnt == 0);

    // Call the fixed_function syscall helper
    ctx.assembler->bla(ff_addresses.syscall);
}

template <typename T>
void codegen_ppc64le<T>::llir$loadstore(gen_context &ctx, const llir::Insn &insn) {
    pr_debug("$loadstore\n");
    assert(insn.dest_cnt == 1);
    assert(insn.src_cnt == 1);

    // We only support zero/sign extension for load reg, X
    assert(insn.loadstore().extension == llir::Extension::NONE
           || ((insn.loadstore().op == llir::LoadStore::Op::LOAD)
               && (insn.dest[0].type() == llir::Operand::Type::REG)));

    // Extract memory and register operands
    auto &memory_operand = (insn.loadstore().op == llir::LoadStore::Op::STORE) ? insn.dest[0] : insn.src[0];
    assert(memory_operand.type() == llir::Operand::Type::MEM);

    auto &reg_operand = (insn.loadstore().op == llir::LoadStore::Op::STORE) ? insn.src[0] : insn.dest[0];
    typename register_allocator<T>::AllocatedGprT reg;
    llir::Register::Mask reg_mask;
    bool zero_others = true;
    auto extension = llir::Extension::NONE;
    bool need_extension_cleanup = false;

    switch (reg_operand.type()) {
        case llir::Operand::Type::REG:
            // Special case: zero/sign extension for load to register
            if (insn.loadstore().op == llir::LoadStore::Op::LOAD &&
                    insn.loadstore().extension != llir::Extension::NONE) {
                extension = insn.loadstore().extension;
                reg_mask = llir$alu$helper$mask_from_width(memory_operand.width);

                // Perform the load to a temporary register with the memory operand's width
                // for aliased registers (!zero_others) OR for sign-extended move to non-64bit register.
                //
                // Zero-extended movs to non-64bit registers with zero-others set will get the correct
                // behavior by default, so we don't need the intermediate register there
                if (reg_operand.reg().zero_others && (extension == llir::Extension::ZERO
                        || reg_operand.reg().mask == llir::Register::Mask::Full64)) {
                    reg = ctx.reg_allocator().get_fixed_gpr(reg_operand.reg());
                } else {
                    reg = ctx.reg_allocator().allocate_gpr();
                    zero_others = true;
                    need_extension_cleanup = true;
                }
                break;
            }

            reg = ctx.reg_allocator().get_fixed_gpr(reg_operand.reg());
            reg_mask = reg_operand.reg().mask;
            zero_others = reg_operand.reg().zero_others;
            break;

        case llir::Operand::Type::IMM:
            assert(insn.loadstore().op == llir::LoadStore::Op::STORE);
            // Stores may also be performed from an immediate rather than a register.
            // Allocate a temporary register and load the immediate to it.
            reg = ctx.reg_allocator().allocate_gpr();
            reg_mask = llir$alu$helper$mask_from_width(reg_operand.width);
            macro$load_imm(*ctx.assembler, reg.gpr(), reg_operand.imm(), llir::Register::Mask::Full64, true);
            break;

        case llir::Operand::Type::MEM:
            assert(insn.loadstore().op == llir::LoadStore::Op::STORE);
            // To support push [mem] we also have to support memory operands for stores
            reg = ctx.reg_allocator().allocate_gpr();
            reg_mask = llir$alu$helper$mask_from_width(reg_operand.width);
            macro$loadstore(ctx, reg.gpr(), reg_operand, llir::LoadStore::Op::LOAD, reg_mask, true, insn);
            break;

        default:
            ASSERT_NOT_REACHED();
    }

    // Emit load/store for the provided register and memory operands
    macro$loadstore(ctx, reg.gpr(), memory_operand, insn.loadstore().op, reg_mask, zero_others, insn, extension);

    if (need_extension_cleanup) {
        // If extension was used and !zero_others, we need to move the result out of the
        // temporary register into the destination.
        auto dest = ctx.reg_allocator().get_fixed_gpr(reg_operand.reg());
        switch (insn.loadstore().extension) {
            case llir::Extension::SIGN:
            case llir::Extension::ZERO:
                // Treat temporary register as target width since macro$loadstore will automatically extend
                macro$move_register_masked(*ctx.assembler, dest.gpr(), reg.gpr(), reg_operand.reg().mask,
                                           reg_operand.reg().mask, reg_operand.reg().zero_others, false);
                break;

            case llir::Extension::NONE:
                ASSERT_NOT_REACHED();
        }
    }
}

//
// Fixed helpers
//

/**
 * fixed_helper$call$emit - Emit the fixed helper for emulating CALL
 *
 * Routine description:
 * Call into retrec C++ code to lookup the host address corresponding to the provided
 * target virtual address. Also stores our return address' {vaddr:haddr} pair to the
 * call stack for fast lookup by a future indirect_jmp call.
 *
 * If the lookup is successful, branch to the target host address. Otherwise, trap to
 * the retrec runtime.
 *
 * Calling convention:
 *   u64 [r1]   - target virtual address of return
 *   lr         - translated address of return
 *   r0         - target virtual address of destination
 *   CR_SCRATCH - clobbered internally
 *
 * All ABIRetrec volatile registers may be clobbered.
 */
template <typename T>
void codegen_ppc64le<T>::fixed_helper$call$emit(gen_context &ctx) {
    constexpr gpr_t GPR_TARGET_ADDR = 0;
    assembler &a = *ctx.assembler;

    // Call virtual_target_lookup_table::lookup_and_update_call_cache to try to resolve the target
    auto &argument_regs = ABIRetrec<T>::argument_regs;

    // Load parameters
    a.ld(llir::PPC64RegisterGPRIndex(argument_regs[0]), GPR_FIXED_RUNTIME_CTX, offsetof(runtime_context_ppc64le, vam)); // this*
    a.ld(llir::PPC64RegisterGPRIndex(argument_regs[1]), GPR_SP, 0);       // Return vaddr
    a.mfspr(llir::PPC64RegisterGPRIndex(argument_regs[2]), SPR::LR);      // Return haddr

    // Load entrypoint
    a.ld(12, GPR_FIXED_RUNTIME_CTX, offsetof(runtime_context_ppc64le, vam_lookup_and_update_call_cache));
    a.mtspr(SPR::CTR, 12);

    // Perform call
    macro$call_native_function(ctx, llir::PPC64RegisterGPRIndex(argument_regs[0]),
                                    GPR_TARGET_ADDR,
                                    llir::PPC64RegisterGPRIndex(argument_regs[1]),
                                    llir::PPC64RegisterGPRIndex(argument_regs[2]));

    // If function returned 0, trap to runtime
    a.cmpldi(CR_SCRATCH, llir::PPC64RegisterGPRIndex(argument_regs[0]), 0);
    a.bc(BO::FIELD_SET, CR_SCRATCH*4 + assembler::CR_EQ, 0); RELOC_FIXUP_LABEL("fh_call_trap", AFTER);

    // Store returned target in ctr
    a.mtspr(SPR::CTR, llir::PPC64RegisterGPRIndex(argument_regs[0]));

    // Jump to target!
    a.bctr();

    // fh_call_trap: Lookup failed - trap to runtime
    RELOC_DECLARE_LABEL_AFTER("fh_call_trap");
    macro$interrupt$trap(ctx, runtime_context_ppc64le::NativeTarget::CALL);
}

/**
 * fixed_helper$call_fixed$emit - Emit the fixed helper for emulating CALL to a known host address
 *
 * Routine description:
 * Perform a direct call to the provided host virtual. Inserts the provided return address'
 * {vaddr:haddr} pair to the call cache for easy lookup in the future. Does NOT call into retrec C++
 * code, since the target host address is already known.
 *
 * `rel` parameter determines whether emitted routine will treat destination address as relative
 * or not.
 *
 * Calling convention:
 *   u64 [r1]   - target virtual address of return
 *   lr         - translated address of return
 *   r0         - host address of destination
 *   CR_SCRATCH - clobbered internally
 *
 * All ABIRetrec volatile registers may be clobbered.
 */
template <typename T>
void codegen_ppc64le<T>::fixed_helper$call_direct$emit(gen_context &ctx, bool rel) {
    constexpr gpr_t GPR_TARGET_ADDR = 0;
    assembler &a = *ctx.assembler;

    {
        // Check if call cache has available slots
        auto vam_ptr = ctx.reg_allocator().allocate_gpr(); // Store pointer to virtual_address_mapper
        auto cc_val = ctx.reg_allocator().allocate_gpr(); // Store dereferenced values
        a.ld(vam_ptr.gpr(), GPR_FIXED_RUNTIME_CTX, offsetof(runtime_context_ppc64le, vam));
        a.ld(cc_val.gpr(), vam_ptr.gpr(), offsetof(virtual_address_mapper, free_cache_entries));
        a.cmpldi(CR_SCRATCH, cc_val.gpr(), 0);
        a.bc(BO::FIELD_SET, CR_SCRATCH*4 + assembler::CR_EQ, 0); RELOC_FIXUP_LABEL("fh_call_direct_skip_cache", AFTER);

        // There are free slots, scan cache in a loop
        a.addi(vam_ptr.gpr(), vam_ptr.gpr(), offsetof(virtual_address_mapper, call_cache));
        auto idx = ctx.reg_allocator().allocate_gpr();
        a.addi(idx.gpr(), 0, 0);
        {
            RELOC_DECLARE_LABEL_AFTER("fh_call_direct_scan_loop");

            // Break if the valid flag is unset
            a.lbzx(cc_val.gpr(), vam_ptr.gpr(), idx.gpr());
            a.cmpldi(CR_SCRATCH, cc_val.gpr(), 0);
            a.bc(BO::FIELD_SET, CR_SCRATCH*4 + assembler::CR_EQ, 0); RELOC_FIXUP_LABEL("fh_call_direct_found_cache_entry", AFTER);

            // Increment index
            a.addi(idx.gpr(), idx.gpr(), sizeof(virtual_address_mapper::call_cache_entry));

            // Keep going if idx < sizeof(call_cache_entry)*CALL_CACHE_SIZE
            a.cmpldi(CR_SCRATCH, idx.gpr(), virtual_address_mapper::CALL_CACHE_SIZE * sizeof(virtual_address_mapper::call_cache_entry));
            a.bc(BO::FIELD_SET, CR_SCRATCH*4 + assembler::CR_LT, 0); RELOC_FIXUP_LABEL("fh_call_direct_scan_loop", BEFORE);
            a.b(0); RELOC_FIXUP_LABEL("fh_call_direct_skip_cache", AFTER); // No free slots
        }

        // vam_ptr+idx points to a free cache entry, populate it with vaddr and haddr of return
        a.addi(cc_val.gpr(), 0, 1); RELOC_DECLARE_LABEL("fh_call_direct_found_cache_entry");
        a.stdux(cc_val.gpr(), idx.gpr(), vam_ptr.gpr()); // valid = 1
        a.ld(cc_val.gpr(), GPR_SP, 0);
        a.stdu(cc_val.gpr(), idx.gpr(), 8); // vaddr = *sp
        a.mfspr(cc_val.gpr(), SPR::LR);
        a.std(cc_val.gpr(), idx.gpr(), 8); // haddr = lr

        // Decrement free_cache_entires and fall through to call
        a.ld(cc_val.gpr(), vam_ptr.gpr(), offsetof(virtual_address_mapper, free_cache_entries));
        a.addi(cc_val.gpr(), cc_val.gpr(), -1);
        a.std(cc_val.gpr(), vam_ptr.gpr(), offsetof(virtual_address_mapper, free_cache_entries));
    }

    // Branch to target
    RELOC_DECLARE_LABEL_AFTER("fh_call_direct_skip_cache");

    if (rel) {
        // If target is relative , add it to LR
        auto tmp_reg = ctx.reg_allocator().allocate_gpr();
        a.mfspr(tmp_reg.gpr(), SPR::LR);
        a.add(GPR_TARGET_ADDR, GPR_TARGET_ADDR, tmp_reg.gpr());
    }

    a.mtspr(SPR::CTR, GPR_TARGET_ADDR);
    a.bctr();
}

/**
 * fixed_helper$indirect_jmp$emit - Emit the fixed helper for emulating indirect jumps
 *
 * Routine description:
 * Call into retrec C++ code to lookup the host address corresponding to the provided
 * target virtual address.
 *
 * If the lookup is successful, branch to the target host address. Otherwise, trap to
 * the retrec runtime.
 *
 * Calling convention:
 *   r0         - Target virtual address of destination
 *   CR_SCRATCH - Clobbered internally
 */
template <typename T>
void codegen_ppc64le<T>::fixed_helper$indirect_jmp$emit(gen_context &ctx) {
    constexpr gpr_t GPR_TARGET_VADDR = 0;
    assembler &a = *ctx.assembler;

    // Call virtual_target_lookup_table::lookup_and_update_call_cache to try to resolve the target
    auto &argument_regs = ABIRetrec<T>::argument_regs;

    // Load parameters
    a.ld(llir::PPC64RegisterGPRIndex(argument_regs[0]), GPR_FIXED_RUNTIME_CTX, offsetof(runtime_context_ppc64le, vam)); // this*

    // Load entrypoint
    a.ld(12, GPR_FIXED_RUNTIME_CTX, offsetof(runtime_context_ppc64le, vam_lookup_check_call_cache));
    a.mtspr(SPR::CTR, 12);

    // Perform call
    macro$call_native_function(ctx, llir::PPC64RegisterGPRIndex(argument_regs[0]), GPR_TARGET_VADDR);

    // If function returned 0, trap to runtime
    a.cmpldi(CR_SCRATCH, llir::PPC64RegisterGPRIndex(argument_regs[0]), 0);
    a.bc(BO::FIELD_SET, CR_SCRATCH*4 + assembler::CR_EQ, 0); RELOC_FIXUP_LABEL("fh_indirect_jmp_trap", AFTER);

    // Store returned target in LR
    a.mtspr(SPR::LR, llir::PPC64RegisterGPRIndex(argument_regs[0]));

    // Jump to target!
    a.blr();

    // fh_ret_trap: Lookup failed - trap to runtime
    RELOC_DECLARE_LABEL_AFTER("fh_indirect_jmp_trap");
    macro$interrupt$trap(ctx, runtime_context_ppc64le::NativeTarget::JUMP);
}

/**
 * Crappy trampoline to perform a relative branch to CTR
 */
template <typename T>
void codegen_ppc64le<T>::fixed_helper$jmp_direct_rel$emit(gen_context &ctx) {
    constexpr gpr_t GPR_TARGET_ADDR = 0;
    assembler &a = *ctx.assembler;

    auto tmp_reg = ctx.reg_allocator().allocate_gpr();
    a.mfspr(tmp_reg.gpr(), SPR::LR);
    a.add(GPR_TARGET_ADDR, GPR_TARGET_ADDR, tmp_reg.gpr());
    a.mtspr(SPR::CTR, GPR_TARGET_ADDR);
    a.bctr();
}

template <typename T>
void codegen_ppc64le<T>::fixed_helper$syscall$emit(gen_context &ctx) {
    macro$interrupt$trap(ctx, runtime_context_ppc64le::NativeTarget::SYSCALL, false);
}

template <typename T>
void codegen_ppc64le<T>::fixed_helper$trap_patch_call$emit(gen_context &ctx) {
    macro$interrupt$trap(ctx, runtime_context_ppc64le::NativeTarget::PATCH_CALL, false);
}

template <typename T>
void codegen_ppc64le<T>::fixed_helper$trap_patch_jump$emit(gen_context &ctx) {
    macro$interrupt$trap(ctx, runtime_context_ppc64le::NativeTarget::PATCH_JUMP, false);
}

/**
 * fixed_helper$imul_overflow$emit - Emit the fixed helper for calculating the status
 * of the overflow and carry flags for an IMUL operation.
 *
 * Routine description:
 * Calculate the state of the overflow/carry flags for the last executed IMUL operation.
 *
 * For 32/64-bit operations, the native XER[OV] flag is directly used, otherwise the result
 * is calculated manually.
 *
 * All ABIRetrec volatile registers may be clobbered.
 */
template <typename T>
void codegen_ppc64le<T>::fixed_helper$imul_overflow$emit(gen_context &ctx) {
    assembler &a = *ctx.assembler;

    // Branch to calculation code for operation type
    a.rldicl(0, GPR_FIXED_FLAG_OP_TYPE, 0, 64-2, false); // Extract FLAG_OP_TYPE[1:0] into r0
    a.cmplwi(CR_SCRATCH, 0, (uint32_t)LastFlagOpData::IMUL_OVERFLOW_16BIT);
    a.bc(BO::FIELD_SET, 4*CR_SCRATCH+assembler::CR_GT, 0); RELOC_FIXUP_LABEL("imul_ov_6432", AFTER); // >  -> 6432
    a.bc(BO::FIELD_SET, 4*CR_SCRATCH+assembler::CR_EQ, 0); RELOC_FIXUP_LABEL("imul_ov_16", AFTER); // == -> 16
    /* else: fallthrough to 8-bit */

    { // 8-bit - Manually calculate OV
        auto tmp = ctx.reg_allocator().allocate_gpr();
        a.extsb(0, GPR_FIXED_FLAG_RES);
        a.rldicl(tmp.gpr(), GPR_FIXED_FLAG_RES, 56, 56);
        a.srawi(0, 0, 7);
        a.rlwinm(0, 0, 0, 24, 31);
        a.cmpw(CR_SCRATCH, 0, tmp.gpr());
        a.crnot(CR_LAZY_FIELD_CARRY, 4*CR_SCRATCH + assembler::CR_EQ);
        a.crnot(CR_LAZY_FIELD_OVERFLOW, 4*CR_SCRATCH + assembler::CR_EQ);
        a.b(0); RELOC_FIXUP_LABEL("imul_ov_common", AFTER);
    }

    { // 16-bit - Manually calculate OV
        auto tmp = ctx.reg_allocator().allocate_gpr();
        a.extsh(0, GPR_FIXED_FLAG_RES); RELOC_DECLARE_LABEL("imul_ov_16");
        a.srwi(tmp.gpr(), GPR_FIXED_FLAG_RES, 16);
        a.srawi(0, 0, 15);
        a.rlwinm(0, 0, 0, 16, 31);
        a.cmpw(CR_SCRATCH, 0, tmp.gpr());
        a.crnot(CR_LAZY_FIELD_CARRY, 4*CR_SCRATCH + assembler::CR_EQ);
        a.crnot(CR_LAZY_FIELD_OVERFLOW, 4*CR_SCRATCH + assembler::CR_EQ);
        a.b(0); RELOC_FIXUP_LABEL("imul_ov_common", AFTER);
    }

    { // 64/32-bit - Use XER[OV] directly
        a.mcrxrx(CR_SCRATCH); RELOC_DECLARE_LABEL("imul_ov_6432");
        a.crmove(CR_LAZY_FIELD_CARRY, 4*CR_SCRATCH + 0);
        a.crmove(CR_LAZY_FIELD_OVERFLOW, 4*CR_SCRATCH + 0);
        /* fallthrough to imul_ov_common */
    }

    // Set LAZYVALID for CF and OF, return
    a.crset(CR_LAZYVALID_CARRY); RELOC_DECLARE_LABEL("imul_ov_common");
    a.crset(CR_LAZYVALID_OVERFLOW);
    a.blr();
}

/**
 * fixed_helper$shift_carry$emit - Emit the fixed helper for calculating the status
 * of the carry flag for a shift operation.
 *
 * Parameters:
 *   - r0 : FLAG_OP_TYPE top field
 * Clobbers:
 *   reg_allocator
 */
template <typename T>
void codegen_ppc64le<T>::fixed_helper$shift_carry$emit(gen_context &ctx) {
    assembler &a = *ctx.assembler;

    // Save cr0
    a.mcrf(CR_SCRATCH, 0);

    // As far as I can tell, a shift with count=0 shouldn't touch CF, so if OP2 is 0
    // just skip to the end where we set LAZYVALID_CARRY.
    //
    // FIXME: This should use a branch hint to be marked as unlikely
    a.cmplwi(0, GPR_FIXED_FLAG_OP2, 0);
    a.bc(BO::FIELD_SET, assembler::CR_EQ, 0); RELOC_FIXUP_LABEL("shift_cf_0shift", AFTER);

    // Determine whether shift was left or right by checking MSBit of OP_ field
    a.rldicl(0, GPR_FIXED_FLAG_OP_TYPE, 64-(uint32_t)LastFlagOpData::OP_TYPE_SHIFT, 63, true);
    a.bc(BO::FIELD_CLR, assembler::CR_EQ, 0); RELOC_FIXUP_LABEL("shift_cf_right", AFTER); // MSBit set, odd, RIGHT
    /* fallthrough to left */

    { // left shift: offset <- RLDICL_OFFSET + shift_count
        a.rldicl(0, GPR_FIXED_FLAG_OP_TYPE, 0, 64-7, false); // Extract rldicl offset
        a.add(0, 0, GPR_FIXED_FLAG_OP2);
        a.b(0); RELOC_FIXUP_LABEL("shift_cf_common", AFTER);
    }

    { // right shift: offset <- RLDICL_OFFSET - shift_count
        a.li(0, 65);
        a.sub(0, 0, GPR_FIXED_FLAG_OP2); RELOC_DECLARE_LABEL("shift_cf_right");
        /* fallthrough to common */
    }

    // Rotate op1 by op2 and mask off all but LSB to get carry flag
    a.rldcl(0, GPR_FIXED_FLAG_OP1, 0, 63, true); RELOC_DECLARE_LABEL("shift_cf_common");

    // Move cf from !cr0.EQ to CR_LAZY
    a.crnot(CR_LAZY_FIELD_CARRY, assembler::CR_EQ);
    a.crset(CR_LAZYVALID_CARRY); RELOC_DECLARE_LABEL("shift_cf_0shift");

    // Restore cr0, return
    a.mcrf(0, CR_SCRATCH);
    a.blr();
}

/**
 * fixed_helper$overflow_carry$emit - Emit the fixed helper for calculating the status
 * of the overflow flag for a shift operation.
 *
 * This routine is pretty poorly optimized but since this is probably a pretty rare flag
 * check it should be fine for now.
 *
 * Parameters:
 *   - r0 : FLAG_OP_TYPE top field
 * Clobbers:
 *   reg_allocator
 */
template <typename T>
void codegen_ppc64le<T>::fixed_helper$shift_overflow$emit(gen_context &ctx) {
    assembler &a = *ctx.assembler;

    // Save cr0
    a.mcrf(CR_SCRATCH, 0);

    // Determine whether shift was left or right by checking MSBit of OP_ field
    a.rldicl(0, GPR_FIXED_FLAG_OP_TYPE, 64-(uint32_t)LastFlagOpData::OP_TYPE_SHIFT, 64-4, true);
    a.cmpwi(0, 0, (uint32_t)LastFlagOpData::OP_SHL >> (uint32_t)LastFlagOpData::OP_TYPE_SHIFT);
    a.bc(BO::FIELD_SET, assembler::CR_LT, 0); RELOC_FIXUP_LABEL("shift_of_shr", AFTER); // LT -> shr
    a.bc(BO::FIELD_SET, assembler::CR_GT, 0); RELOC_FIXUP_LABEL("shift_of_sar", AFTER); // GT -> sar
    /* fallthrough to left */

    { // left shift: OF = (OP1[MSB] != OP1[MSB-1])
        auto tmp = ctx.reg_allocator().allocate_gpr();

        // Shift MSB and MSB-1 into the LSBs of r0
        a.rldicl(tmp.gpr(), GPR_FIXED_FLAG_OP_TYPE, 0, 64-7, false); // Extract rldicl offset
        a.addi(0, tmp.gpr(), 2); // Add offset of 2 for 2 MSBs
        a.rldcl(0, GPR_FIXED_FLAG_OP1, 0, 62, false);

        // Compare 2 LSBs of r0
        a.rldicl(tmp.gpr(), 0, 64-1, 63, false);
        a.rldicl(0, 0, 0, 63, false);
        a.cmpw(0, 0, tmp.gpr()); // CR0[eq] <- !OF

        a.crnot(CR_LAZY_FIELD_OVERFLOW, 4*0 + assembler::CR_EQ);
        a.b(0); RELOC_FIXUP_LABEL("shift_of_common", AFTER);
    }

    { // right shift (logical): OF=OP1[MSB]
        auto tmp = ctx.reg_allocator().allocate_gpr();

        // Shift MSB and MSB-1 into the LSBs of r0
        a.rldicl(tmp.gpr(), GPR_FIXED_FLAG_OP_TYPE, 0, 64-7, false); RELOC_DECLARE_LABEL("shift_of_shr");
        a.addi(0, tmp.gpr(), 1); // Add offset of 1 for 1 MSBs
        a.rldcl(0, GPR_FIXED_FLAG_OP1, 0, 63, true);

        a.crnot(CR_LAZY_FIELD_OVERFLOW, 4*0 + assembler::CR_EQ); // OF <- !CR0[eq]
        a.b(0); RELOC_FIXUP_LABEL("shift_of_common", AFTER);
    }

    { // right shift (arithmetic): OF=0
        a.crclr(CR_LAZY_FIELD_OVERFLOW); RELOC_DECLARE_LABEL("shift_of_sar");
        /* fallthrough to common */
    }

    // Restore cr0, return
    a.crset(CR_LAZYVALID_OVERFLOW); RELOC_DECLARE_LABEL("shift_of_common");
    a.mcrf(0, CR_SCRATCH);
    a.blr();
}

template <typename T>
void codegen_ppc64le<T>::fixed_helper$cpuid$emit(gen_context &ctx) {
    assembler &a = *ctx.assembler;

    // Save LR
    a.mfspr(0, SPR::LR);
    a.stdu(0, 1, -8);

    // Allocate a buffer for the result
    auto out_ptr_reg = llir::PPC64RegisterGPRIndex(ABIRetrec<T>::argument_regs[0]);
    a.addi(1, 1, (int16_t)sizeof(x86_64::CpuidResult) * -1);
    a.mr(out_ptr_reg, 1);

    {
        // The function and subfunc for rax are stored in EAX, ECX
        auto func_reg = ctx.reg_allocator().get_fixed_gpr(llir::X86_64Register::RAX);
        auto subfunc_reg = ctx.reg_allocator().get_fixed_gpr(llir::X86_64Register::RCX);

        // Call x86_64::get_cpuid
        macro$load_imm(a, 12, (uintptr_t)&x86_64::get_cpuid, llir::Register::Mask::Full64, true);
        a.mtspr(SPR::CTR, 12);
        macro$call_native_function(ctx, func_reg.gpr(), subfunc_reg.gpr(), out_ptr_reg);
    }

    // Load EAX,EBX,ECX,EDX from result
    auto eax = ctx.reg_allocator().get_fixed_gpr(llir::X86_64Register::RAX);
    auto ebx = ctx.reg_allocator().get_fixed_gpr(llir::X86_64Register::RBX);
    auto ecx = ctx.reg_allocator().get_fixed_gpr(llir::X86_64Register::RCX);
    auto edx = ctx.reg_allocator().get_fixed_gpr(llir::X86_64Register::RDX);
    a.lwz(eax.gpr(), 1, 0);
    a.lwz(ebx.gpr(), 1, 4);
    a.lwz(ecx.gpr(), 1, 8);
    a.lwz(edx.gpr(), 1, 12);

    // Restore stack frame, LR
    a.ld(0, 1, 16);
    a.mtspr(SPR::LR, 0);
    a.addi(1, 1, sizeof(x86_64::CpuidResult) + 8);

    a.blr();
}

/**
 * fixed_helper$mul_overflow$emit - Emit the fixed helper for calculating the status
 * of the overflow and carry flags for a MUL operation.
 *
 * Routine description:
 * Calculate the state of the overflow/carry flags for the last executed MUL operation.
 *
 * Clobbers:
 *  - r0
 *  - reg_allocator
 *  - CR_SCRATCH
 */
template <typename T>
void codegen_ppc64le<T>::fixed_helper$mul_overflow$emit(gen_context &ctx) {
    assembler &a = *ctx.assembler;

    // Preserve cr0 in CR_SCRATCH
    a.mcrf(CR_SCRATCH, 0);

    // Branch to calculation code for operation type
    a.rldicl(0, GPR_FIXED_FLAG_OP_TYPE, 0, 64-2, false); // Extract FLAG_OP_TYPE[1:0] into r0
    a.cmplwi(0, 0, (uint32_t)LastFlagOpData::IMUL_OVERFLOW_32BIT);
    a.bc(BO::FIELD_SET, 4*0+assembler::CR_GT, 0); RELOC_FIXUP_LABEL("mul_ov_64", AFTER); // >  -> 64
    a.bc(BO::FIELD_SET, 4*0+assembler::CR_EQ, 0); RELOC_FIXUP_LABEL("mul_ov_32", AFTER); // == -> 32
    a.cmplwi(0, 0, (uint32_t)LastFlagOpData::IMUL_OVERFLOW_16BIT);
    a.bc(BO::FIELD_SET, 4*0+assembler::CR_EQ, 0); RELOC_FIXUP_LABEL("mul_ov_16", AFTER); // ==  -> 16
    /* else: fallthrough to 8-bit */

    { // 8-bit
        a.rldicl(0, GPR_FIXED_FLAG_RES, 64-8, 64-8, true);
        a.b(0); RELOC_FIXUP_LABEL("mul_ov_common", AFTER);
    }

    { // 16-bit
        a.rldicl(0, GPR_FIXED_FLAG_RES, 64-16, 64-16, true); RELOC_DECLARE_LABEL("mul_ov_16");
        a.b(0); RELOC_FIXUP_LABEL("mul_ov_common", AFTER);
    }

    { // 32-bit
        a.rldicl(0, GPR_FIXED_FLAG_RES, 64-32, 64-32, true); RELOC_DECLARE_LABEL("mul_ov_32");
        a.b(0); RELOC_FIXUP_LABEL("mul_ov_common", AFTER);
    }

    { // 64-bit
        a.mulhdu(0, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2, true); RELOC_DECLARE_LABEL("mul_ov_64");
        /* fallthrough to mul_ov_common */
    }

    // Move OF from !cr0[eq] to CR_LAZY_FIELD_CARRY, CR_LAZY_FIELD_OVERFLOW
    a.crnot(CR_LAZY_FIELD_CARRY, 4*0 + assembler::CR_EQ); RELOC_DECLARE_LABEL("mul_ov_common");
    a.crnot(CR_LAZY_FIELD_OVERFLOW, 4*0 + assembler::CR_EQ);

    // Set LAZYVALID for CF and OF, return
    a.crset(CR_LAZYVALID_CARRY);
    a.crset(CR_LAZYVALID_OVERFLOW);

    // Restore cr0, return
    a.mcrf(0, CR_SCRATCH);
    a.blr();
}


//
// Macro assembler
//

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
    assembler &a = *ctx.assembler;
    auto cr_save_reg = ctx.reg_allocator().allocate_gpr(); // not used for shift, imul, mul

    // Skip to last instruction if CF has already been evaluated
    a.bc(BO::FIELD_SET, CR_LAZYVALID_CARRY, 0); RELOC_FIXUP_LABEL("cf_skip", AFTER);

    // Branch to calculation code for operation type
    a.rldicl(0, GPR_FIXED_FLAG_OP_TYPE, 64-(uint32_t)LastFlagOpData::OP_TYPE_SHIFT, 64-4, false); // Extract FLAG_OP_TYPE[15:12] into r0
    a.cmpldi(CR_SCRATCH, 0, (uint32_t)LastFlagOpData::OP_IMUL >> (uint32_t)LastFlagOpData::OP_TYPE_SHIFT);
    a.bc(BO::FIELD_SET, 4*CR_SCRATCH+assembler::CR_LT, 0); RELOC_FIXUP_LABEL("cf_addsub", AFTER); // Less than IMUL -> ADD/SUB
    a.bc(BO::FIELD_SET, 4*CR_SCRATCH+assembler::CR_EQ, 0); RELOC_FIXUP_LABEL("cf_imul", AFTER);   // Equals -> IMUL
    a.cmpldi(CR_SCRATCH, 0, (uint32_t)LastFlagOpData::OP_SHR >> (uint32_t)LastFlagOpData::OP_TYPE_SHIFT);
    a.bc(BO::FIELD_SET, 4*CR_SCRATCH+assembler::CR_LT, 0); RELOC_FIXUP_LABEL("cf_mul", AFTER); // Less than SHR -> MUL
    /* Else, fallthrough to shift */

    { // cf_shift
        // Call shift_carry fixed helper
        a.bla(ff_addresses.shift_carry); RELOC_DECLARE_LABEL("cf_shift");
        a.b(0); RELOC_FIXUP_LABEL("cf_skip", AFTER);
    }

    { // cf_imul
        // Call imul_overflow OF fixed helper
        a.bla(ff_addresses.imul_overflow); RELOC_DECLARE_LABEL("cf_imul");
        a.b(0); RELOC_FIXUP_LABEL("cf_skip", AFTER);
    }

    { // cf_mul
        // Call mul_overflow OF fixed helper
        a.bla(ff_addresses.mul_overflow); RELOC_DECLARE_LABEL("cf_mul");
        a.b(0); RELOC_FIXUP_LABEL("cf_skip", AFTER);
    }

    { // cf_addsub
        // Preserve cr0 in a scratch register
        a.mfcr(cr_save_reg.gpr());  RELOC_DECLARE_LABEL("cf_addsub");

        // Load CARRY_* field into r0 (FLAG_OP_TYPE[5:0])
        a.rldicl(0, GPR_FIXED_FLAG_OP_TYPE, 0, 64-6 /* 6-bits */, false);

        // 64-bit add/sub needs special handling
        a.cmpldi(CR_SCRATCH, 0, enum_cast(LastFlagOpData::CARRY_DOUBLEWORD_ADD));
        a.bc(BO::FIELD_SET, 4*CR_SCRATCH+assembler::CR_EQ, 0); RELOC_FIXUP_LABEL("cf_add64", AFTER); // == -> ADD64
        a.bc(BO::FIELD_SET, 4*CR_SCRATCH+assembler::CR_GT, 0); RELOC_FIXUP_LABEL("cf_sub64", AFTER); // >  -> SUB64

        // Otherwise, extract the carry bit according to the CARRY_* field
        a.rldcl(0, GPR_FIXED_FLAG_RES, 0, 63, true); // Put overflow flag into !cr0[eq]
        a.b(0); RELOC_FIXUP_LABEL("cf_addsub_common", AFTER);
    }

    { // cf_add64
        // Calculate carry bit and set cr0[eq] accordingly.
        a.subc(0, GPR_FIXED_FLAG_RES, GPR_FIXED_FLAG_OP1); RELOC_DECLARE_LABEL("cf_add64");
        a.sube_(0, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP1); // Put overflow flag into !cr0[eq]
        a.b(0); RELOC_FIXUP_LABEL("cf_addsub_common", AFTER);
    }

    { // cf_sub64
        // Calculate carry bit and set cr0[eq] accordingly.
        a.subc(0, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_RES); RELOC_DECLARE_LABEL("cf_sub64");
        a.sube_(0, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP1); // Put overflow flag into !cr0[eq]
        /* fallthrough */
    }

    // cf_addsub_common - move CF from !cr0[eq] to CR_LAZY_FIELD_CARRY
    a.crnot(CR_LAZY_FIELD_CARRY, 4*0 + assembler::CR_EQ); RELOC_DECLARE_LABEL("cf_addsub_common");

    // Set CR_LAZYVALID_CARRY
    a.crset(CR_LAZYVALID_CARRY);

    // Restore cr0 and return
    a.mtcrf(0x80, cr_save_reg.gpr());
    RELOC_DECLARE_LABEL_AFTER("cf_skip");
}

template <typename T>
void codegen_ppc64le<T>::macro$branch$conditional$overflow(gen_context &ctx) {
    assembler &a = *ctx.assembler;

    // Skip to last instruction if OF has already been evaluated
    a.bc(BO::FIELD_SET, CR_LAZYVALID_OVERFLOW, 0); RELOC_FIXUP_LABEL("of_skip", AFTER);

    // Allocate scratch registers for use in calculation (not used for shift,imul,mul)
    auto scratch1 = ctx.reg_allocator().allocate_gpr();

    // Branch to calculation code for operation type
    a.rldicl(0, GPR_FIXED_FLAG_OP_TYPE, 64-(uint32_t)LastFlagOpData::OP_TYPE_SHIFT, 64-4, false); // Extract FLAG_OP_TYPE[16:12] into r0

    a.cmpldi(CR_SCRATCH, 0, (uint32_t)LastFlagOpData::OP_ADD >> (uint32_t)LastFlagOpData::OP_TYPE_SHIFT);
    a.bc(BO::FIELD_SET, 4*CR_SCRATCH+assembler::CR_LT, 0); RELOC_FIXUP_LABEL("of_sub", AFTER); // Less than ADD -> SUB
    a.bc(BO::FIELD_SET, 4*CR_SCRATCH+assembler::CR_EQ, 0); RELOC_FIXUP_LABEL("of_add", AFTER); // Equal to ADD
    a.cmpldi(CR_SCRATCH, 0, (uint32_t)LastFlagOpData::OP_MUL >> (uint32_t)LastFlagOpData::OP_TYPE_SHIFT);
    a.bc(BO::FIELD_SET, 4*CR_SCRATCH+assembler::CR_LT, 0); RELOC_FIXUP_LABEL("of_imul", AFTER); // Less than MUL -> IMUL
    a.bc(BO::FIELD_SET, 4*CR_SCRATCH+assembler::CR_EQ, 0); RELOC_FIXUP_LABEL("of_mul", AFTER);  // Equals -> MUL
    // Else, fallthrough to shift

    { // shift
        a.bla(ff_addresses.shift_overflow);
        a.b(0); RELOC_FIXUP_LABEL("of_skip", AFTER);
    }

    { // IMUL
        // Call imul_overflow OF fixed helper
        a.bla(ff_addresses.imul_overflow); RELOC_DECLARE_LABEL("of_imul");
        a.b(0); RELOC_FIXUP_LABEL("of_skip", AFTER);
    }

    { // MUL
        // Call mul_overflow OF fixed helper
        a.bla(ff_addresses.mul_overflow); RELOC_DECLARE_LABEL("of_mul");
        a.b(0); RELOC_FIXUP_LABEL("of_skip", AFTER);
    }

    { // ADD
        a.add(scratch1.gpr(), GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2); RELOC_DECLARE_LABEL("of_add");
        a.eqv(0, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2);
        a._xor(scratch1.gpr(), scratch1.gpr(), GPR_FIXED_FLAG_OP2);
        a._and(0, 0, scratch1.gpr());
        a.b(0); RELOC_FIXUP_LABEL("of_addsub_common", AFTER); // Branch to common shifting code
    }

    { // SUB
        a.sub(scratch1.gpr(), GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2); RELOC_DECLARE_LABEL("of_sub");
        a._xor(0, GPR_FIXED_FLAG_OP1, GPR_FIXED_FLAG_OP2);
        a.eqv(scratch1.gpr(), scratch1.gpr(), GPR_FIXED_FLAG_OP2);
        a._and(0, 0, scratch1.gpr());
        // fall through to common shifting code
    }

    // The overflow bit is now in r0. Depending on operation width, shift it into bit 0, and clear all left.
    RELOC_DECLARE_LABEL_AFTER("of_addsub_common");
    a.rldicl(scratch1.gpr(), GPR_FIXED_FLAG_OP_TYPE, 64-(uint32_t)LastFlagOpData::OVERFLOW_SHIFT, 64-6, false);
    a.rldcl(0, 0, scratch1.gpr(), 63, false); // Put overflow flag into r0[0]
    a.cmpldi(CR_SCRATCH, 0, 1);

    // CR_SCRATCH[eq] now contains the Overflow flag. Move it into CR_LAZY[OVERFLOW].
    a.crmove(CR_LAZY_FIELD_OVERFLOW, 4*CR_SCRATCH + assembler::CR_EQ);

    // Mark OF as valid
    a.crset(CR_LAZYVALID_OVERFLOW);
    RELOC_DECLARE_LABEL_AFTER("of_skip");
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
                                                    llir::Register::Mask dest_mask, bool zero_others, bool modify_cr,
                                                    llir::Extension extension) {
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
    bool clear_extra_bits = extension == llir::Extension::ZERO;

    if (zero_others) {
        switch (extension) {
            case llir::Extension::NONE:
                // If we don't care about extension, just move the register
                assembler.mr(dest, src);
                break;

            case llir::Extension::SIGN:
            case llir::Extension::ZERO:
            {
                // If we don't care about preserving others and will clear/extend the top bits, we can get away with an rldicl
                uint8_t sh = (uint8_t)(64 - src_shift + dest_shift) % 64;
                uint8_t me = (uint8_t)(64 - std::min(dest_width, src_width) - dest_shift);

                assembler.rldicl(dest, src, sh, me, modify_cr);

                // If the destination isn't right-justified, clear the extra right bits
                if (dest_shift)
                    assembler.rldicr(dest, dest, 0, 64-dest_shift, modify_cr);

                if (src_width < dest_width) {
                    // Clear extra bits on left
                    if (extension == llir::Extension::ZERO) {
                        assembler.rldicl(dest, dest, 0, (uint8_t)(64-dest_width-dest_shift), modify_cr);
                    } else {
                        if (dest_shift)
                            TODO();
                        switch (src_mask) {
                            case llir::Register::Mask::Full64:
                                break;
                            case llir::Register::Mask::Low32:
                                assembler.extsw(dest, dest);
                                break;
                            case llir::Register::Mask::LowLow16:
                                assembler.extsh(dest, dest);
                                break;
                            case llir::Register::Mask::LowLowHigh8:
                            case llir::Register::Mask::LowLowLow8:
                                assembler.extsb(dest, dest);
                                break;
                            default:
                                TODO();
                        }
                    }
                }

                break;
            }
        }
    } else {
        if (!src_shift) {
            // If the source isn't shifted, this can be accomplished with rldimi
            assembler.insrdi(dest, src, dest_width, (uint8_t)(64-(dest_width + dest_shift)), modify_cr);

            if (clear_extra_bits && (dest_width > src_width)) {
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

                if (clear_extra_bits && (dest_width > src_width))
                    TODO();
            } else { TODO(); }
        }
    }
}

template <typename T>
void codegen_ppc64le<T>::macro$loadstore(gen_context &, gpr_t, const llir::Operand &, llir::LoadStore::Op,
                                         llir::Register::Mask, bool, const llir::Insn &, llir::Extension) {
    static_assert(std::is_same_v<T, T>, "Missing macro$loadstore specialization for target arch!");
}

// Specialization of macro$loadstore for x86_64 targets
template <>
void codegen_ppc64le<TargetTraitsX86_64>::macro$loadstore(gen_context &ctx, gpr_t reg,
                     const llir::Operand &mem_op, llir::LoadStore::Op op, llir::Register::Mask reg_mask,
                     bool reg_zero_others, const llir::Insn &insn, llir::Extension extension) {
    auto mem = mem_op.memory();
    auto update = mem.update;
    auto mem_width = mem_op.width;
    auto &x86_64 = mem.x86_64();
    bool sign_ext = extension == llir::Extension::SIGN;
    assert(mem_width == mask_to_width(reg_mask));
    uint64_t tls_base_off = 0;

    // Partially handle segment for TLS
    switch (mem.x86_64().segment.x86_64) {
        case llir::X86_64Register::FS:
            // Use the emulated CPU context's FS register as the TLS base
            tls_base_off = offsetof(runtime_context_ppc64le, x86_64_ucontext)
                             + offsetof(cpu_context_x86_64, segments[0]);
            break;
        case llir::X86_64Register::GS:
            // Use the emulated CPU context's FS register as the TLS base
            tls_base_off = offsetof(runtime_context_ppc64le, x86_64_ucontext)
                             + offsetof(cpu_context_x86_64, segments[1]);
            break;
        case llir::X86_64Register::INVALID:
            // No segment, treat normally
            break;
        default:
            TODO();
    }

    // Wrappers for load{displacement, indexed} with {zero, sign} extension, with emulation
    // for instructions that don't exist.
    auto ld    = [&](auto a, auto b, auto c) { ctx.assembler->ld(a, b, c); };
    auto ldu   = [&](auto a, auto b, auto c) { ctx.assembler->ldu(a, b, c); };
    auto ldx   = [&](auto a, auto b, auto c) { ctx.assembler->ldx(a, b, c); };
    auto ldux  = [&](auto a, auto b, auto c) { ctx.assembler->ldux(a, b, c); };

    auto lwz   = [&](auto a, auto b, auto c) { ctx.assembler->lwz(a, b, c); };
    auto lwzu  = [&](auto a, auto b, auto c) { ctx.assembler->lwzu(a, b, c); };
    auto lwzx  = [&](auto a, auto b, auto c) { ctx.assembler->lwzx(a, b, c); };
    auto lwzux = [&](auto a, auto b, auto c) { ctx.assembler->lwzux(a, b, c); };
    auto lwa   = [&](auto a, auto b, auto c) { ctx.assembler->lwa(a, b, c); };
    auto lwau  = [&](auto a, auto b, auto c) { ctx.assembler->lwa(a, b, c); ctx.assembler->addi(b, b, c); };
    auto lwax  = [&](auto a, auto b, auto c) { ctx.assembler->lwax(a, b, c); };
    auto lwaux = [&](auto a, auto b, auto c) { ctx.assembler->lwaux(a, b, c); };

    auto lhz   = [&](auto a, auto b, auto c) { ctx.assembler->lhz(a, b, c); };
    auto lhzu  = [&](auto a, auto b, auto c) { ctx.assembler->lhzu(a, b, c); };
    auto lhzx  = [&](auto a, auto b, auto c) { ctx.assembler->lhzx(a, b, c); };
    auto lhzux = [&](auto a, auto b, auto c) { ctx.assembler->lhzux(a, b, c); };
    auto lha   = [&](auto a, auto b, auto c) { ctx.assembler->lha(a, b, c); };
    auto lhau  = [&](auto a, auto b, auto c) { ctx.assembler->lhau(a, b, c); };
    auto lhax  = [&](auto a, auto b, auto c) { ctx.assembler->lhax(a, b, c); };
    auto lhaux = [&](auto a, auto b, auto c) { ctx.assembler->lhaux(a, b, c); };

    auto lbz   = [&](auto a, auto b, auto c) { ctx.assembler->lbz(a, b, c); };
    auto lbzu  = [&](auto a, auto b, auto c) { ctx.assembler->lbzu(a, b, c); };
    auto lbzx  = [&](auto a, auto b, auto c) { ctx.assembler->lbzx(a, b, c); };
    auto lbzux = [&](auto a, auto b, auto c) { ctx.assembler->lbzux(a, b, c); };
    auto lba   = [&](auto a, auto b, auto c) { ctx.assembler->lbz(a, b, c); ctx.assembler->extsb(a, a); };
    auto lbau  = [&](auto a, auto b, auto c) { ctx.assembler->lbzu(a, b, c); ctx.assembler->extsb(a, a); };
    auto lbax  = [&](auto a, auto b, auto c) { ctx.assembler->lbzx(a, b, c); ctx.assembler->extsb(a, a); };
    auto lbaux = [&](auto a, auto b, auto c) { ctx.assembler->lbzux(a, b, c); ctx.assembler->extsb(a, a); };

// Helpers to call the appropriate loadstore op depending on whether `update` is set or not
#define LOAD_DISP(op, ...) ((update == llir::MemOp::Update::PRE) ? op ## u(__VA_ARGS__) : op(__VA_ARGS__))
#define LOAD_INDEXED(op, ...) ((update == llir::MemOp::Update::PRE) ? op ## ux(__VA_ARGS__) : op ## x(__VA_ARGS__))
#define STORE_DISP(op, ...) ((update == llir::MemOp::Update::PRE) ? ctx.assembler->op ## u(__VA_ARGS__) : ctx.assembler->op(__VA_ARGS__))
#define STORE_INDEXED(op, ...) ((update == llir::MemOp::Update::PRE) ? ctx.assembler->op ## ux(__VA_ARGS__) : ctx.assembler->op ## x(__VA_ARGS__))

    // Wrappers for performing loads with appropriate update and extension
    auto ld_  = [&](auto dest, auto ra, auto disp) { return LOAD_DISP(ld, dest, ra, disp); };
    auto lw_  = [&](auto dest, auto ra, auto disp) { return sign_ext ? LOAD_DISP(lwa, dest, ra, disp) : LOAD_DISP(lwz, dest, ra, disp); };
    auto lh_  = [&](auto dest, auto ra, auto disp) { return sign_ext ? LOAD_DISP(lha, dest, ra, disp) : LOAD_DISP(lhz, dest, ra, disp); };
    auto lb_  = [&](auto dest, auto ra, auto disp) { return sign_ext ? LOAD_DISP(lba, dest, ra, disp) : LOAD_DISP(lbz, dest, ra, disp); };
    auto ldx_ = [&](auto dest, auto ra, auto disp) { return LOAD_INDEXED(ld, dest, ra, disp); };
    auto lwx_ = [&](auto dest, auto ra, auto disp) { return sign_ext ? LOAD_INDEXED(lwa, dest, ra, disp) : LOAD_INDEXED(lwz, dest, ra, disp); };
    auto lhx_ = [&](auto dest, auto ra, auto disp) { return sign_ext ? LOAD_INDEXED(lha, dest, ra, disp) : LOAD_INDEXED(lhz, dest, ra, disp); };
    auto lbx_ = [&](auto dest, auto ra, auto disp) { return sign_ext ? LOAD_INDEXED(lba, dest, ra, disp) : LOAD_INDEXED(lbz, dest, ra, disp); };

#undef LOAD_DISP
#undef LOAD_INDEXED

    auto loadstore_disp = [&](gpr_t reg, gpr_t ra, int16_t disp) {
        if (op == llir::LoadStore::Op::LOAD) {
            gpr_t dest = reg;
            register_allocator<TargetTraitsX86_64>::AllocatedGprT tmp;

            if (!reg_zero_others) {
                tmp = ctx.reg_allocator().allocate_gpr();
                dest = tmp.gpr();
            }

            switch (reg_mask) {
                case llir::Register::Mask::Full64: ld_(dest, ra, disp); break;
                case llir::Register::Mask::Low32: lw_(dest, ra, disp); break;
                case llir::Register::Mask::LowLow16: lh_(dest, ra, disp); break;
                case llir::Register::Mask::LowLowLow8: lb_(dest, ra, disp); break;
                case llir::Register::Mask::LowLowHigh8:
                {
                    // FIXME: There's probably a more intelligent way to do this
                    auto temp = ctx.reg_allocator().allocate_gpr();
                    lb_(temp.gpr(), ra, disp);
                    macro$move_register_masked(*ctx.assembler, reg, temp.gpr(),
                                               llir::Register::Mask::LowLowLow8,
                                               llir::Register::Mask::LowLowHigh8, false, false);
                    assert(!reg_zero_others);
                    return; // Skip zero_others cleanup code
                }
                case llir::Register::Mask::Special: TODO();
            }

            if (!reg_zero_others)
                macro$move_register_masked(*ctx.assembler, reg, dest, reg_mask, reg_mask, false, false);

        } else if (op == llir::LoadStore::Op::STORE) {
            switch (reg_mask) {
                case llir::Register::Mask::Full64: STORE_DISP(std, reg, ra, disp); break;
                case llir::Register::Mask::Low32: STORE_DISP(stw, reg, ra, disp); break;
                case llir::Register::Mask::LowLow16: STORE_DISP(sth, reg, ra, disp); break;
                case llir::Register::Mask::LowLowLow8: STORE_DISP(stb, reg, ra, disp); break;
                case llir::Register::Mask::LowLowHigh8:
                {
                    auto temp = ctx.reg_allocator().allocate_gpr();
                    macro$move_register_masked(*ctx.assembler, temp.gpr(), reg,
                                               llir::Register::Mask::LowLowHigh8,
                                               llir::Register::Mask::LowLowLow8, false, false);
                    STORE_DISP(stb, temp.gpr(), ra, disp);
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
            gpr_t dest = reg;
            register_allocator<TargetTraitsX86_64>::AllocatedGprT tmp;
            if (!reg_zero_others) {
                tmp = ctx.reg_allocator().allocate_gpr();
                dest = tmp.gpr();
            }

            switch (reg_mask) {
                case llir::Register::Mask::Full64: ldx_(dest, ra, rb); break;
                case llir::Register::Mask::Low32: lwx_(dest, ra, rb); break;
                case llir::Register::Mask::LowLow16: lhx_(dest, ra, rb); break;
                case llir::Register::Mask::LowLowLow8: lbx_(dest, ra, rb); break;
                case llir::Register::Mask::LowLowHigh8:
                {
                    auto temp = ctx.reg_allocator().allocate_gpr();
                    lbx_(temp.gpr(), ra, rb);
                    macro$move_register_masked(*ctx.assembler, reg, temp.gpr(),
                                               llir::Register::Mask::LowLowLow8,
                                               llir::Register::Mask::LowLowHigh8, false, false);
                    assert(!reg_zero_others);
                    return; // Skip zero_others cleanup code
                }
                case llir::Register::Mask::Special: TODO();
            }

            if (!reg_zero_others)
                macro$move_register_masked(*ctx.assembler, reg, dest, reg_mask, reg_mask, false, false);

        } else if (op == llir::LoadStore::Op::STORE) {
            switch (reg_mask) {
                case llir::Register::Mask::Full64: STORE_INDEXED(std, reg, ra, rb); break;
                case llir::Register::Mask::Low32: STORE_INDEXED(stw, reg, ra, rb); break;
                case llir::Register::Mask::LowLow16: STORE_INDEXED(sth, reg, ra, rb); break;
                case llir::Register::Mask::LowLowLow8: STORE_INDEXED(stb, reg, ra, rb); break;
                case llir::Register::Mask::LowLowHigh8:
                {
                    auto temp = ctx.reg_allocator().allocate_gpr();
                    macro$move_register_masked(*ctx.assembler, temp.gpr(), reg,
                                               llir::Register::Mask::LowLowHigh8,
                                               llir::Register::Mask::LowLowLow8, false, false);
                    STORE_INDEXED(stb, temp.gpr(), ra, rb);
                    break;
                }
                case llir::Register::Mask::Special: TODO();
            }
        } else if (op == llir::LoadStore::Op::LEA) {
            // Load calculated address into reg
            ctx.assembler->add(reg, ra, rb);
        } else { TODO(); }
    };

#undef STORE_DISP
#undef STORE_INDEXED

    auto loadstore_disp_auto = [&](gpr_t reg, gpr_t ra, int64_t disp) {
        // If the operation uses post increment, use a displacement of 0 and add disp to ra afterwards.
        if (update == llir::MemOp::Update::POST) {
            loadstore_disp(reg, ra, 0);
            if (!x86_64.disp_sign_from_df) {
                macro$alu$add_imm(ctx, ra, x86_64.disp);
            } else {
                auto temp = ctx.reg_allocator().allocate_gpr();
                macro$load_imm(*ctx.assembler, temp.gpr(), disp, llir::Register::Mask::Full64, true);

                // Negate if DF is set
                ctx.assembler->bc(BO::FIELD_CLR, CR_MISCFLAGS_FIELD_DIRECTION, 2 * 4);
                ctx.assembler->neg(temp.gpr(), temp.gpr());
                ctx.assembler->add(ra, ra, temp.gpr());
            }
            return;
        }

        // Otherwise, use the provided displacement for the load/store
        assert(!x86_64.disp_sign_from_df); // Add support in the future if necessary

        bool disp_fits;
        if (op == llir::LoadStore::Op::LEA || (reg_mask != llir::Register::Mask::Full64
            && !(reg_mask == llir::Register::Mask::Low32 && extension == llir::Extension::SIGN)))
            // For LEA, <64-bit loads/stores, and !lwa, check if the mask fits in 16-bit disp field
            disp_fits = assembler::fits_in_mask(disp, 0xFFFFU);
        else
            // For 64-bit loads/stores, the displacement must have the two least significant bits cleared
            disp_fits = assembler::fits_in_mask(disp, 0xFFFCU);


        if (disp_fits) {
            if (tls_base_off) {
                // A segment register was selected, grab it from the runtime context and add it to ra
                assert(update == llir::MemOp::Update::NONE);
                auto temp = ctx.reg_allocator().allocate_gpr();
                ctx.assembler->ld(temp.gpr(), GPR_FIXED_RUNTIME_CTX, (int16_t)tls_base_off);
                ctx.assembler->add(temp.gpr(), temp.gpr(), ra);
                loadstore_disp(reg, temp.gpr(), (int16_t)disp);
            } else {
                // Fits in an immediate displacement field
                loadstore_disp(reg, ra, (int16_t)disp);
            }
        } else {
            // Need to load into a gpr before operation
            auto temp = ctx.reg_allocator().allocate_gpr();
            macro$load_imm(*ctx.assembler, temp.gpr(), disp, llir::Register::Mask::Full64, true);
            if (tls_base_off) {
                ctx.assembler->ld(temp.gpr(), GPR_FIXED_RUNTIME_CTX, (int16_t)tls_base_off);
                ctx.assembler->add(temp.gpr(), temp.gpr(), ra);
            }

            loadstore_indexed(reg, ra, temp.gpr());
        }
    };


    typename register_allocator<TargetTraitsX86_64>::AllocatedGprT *orig_base = nullptr;
    typename register_allocator<TargetTraitsX86_64>::AllocatedGprT orig_base_storage, base, index;

    // Obtain GPRs for base and index if present
    if (x86_64.base.x86_64 != llir::X86_64Register::INVALID) {
        if (x86_64.base.x86_64 == llir::X86_64Register::RIP) {
            // Special case: RIP-relative addressing
            // Load the next instruction's address into a temporary GPR and use that as base
            base = ctx.reg_allocator().allocate_gpr();
            orig_base = &base;
            uint64_t next_rip = insn.address + insn.size;
            macro$load_imm(*ctx.assembler, base.gpr(), next_rip, llir::Register::Mask::Full64, true);
        } else if (x86_64.base.mask == llir::Register::Mask::Full64) {
            // Base is a 64-bit register that can be used directly
            base = ctx.reg_allocator().get_fixed_gpr(x86_64.base);
            orig_base = &base;
        } else {
            // Base needs to be moved out of an aliased register into a temporary
            orig_base_storage = ctx.reg_allocator().get_fixed_gpr(x86_64.base);
            orig_base = &orig_base_storage;
            base = ctx.reg_allocator().allocate_gpr();
            macro$move_register_masked(*ctx.assembler, base.gpr(), orig_base_storage.gpr(), x86_64.base.mask,
                                       llir::Register::Mask::Full64, true, false);
        }
    }

    if (x86_64.index.x86_64 != llir::X86_64Register::INVALID) {
        index = ctx.reg_allocator().get_fixed_gpr(x86_64.index);
        // If register is <64-bits OR has a scale, allocate a temporary and use that.
        if (x86_64.index.mask != llir::Register::Mask::Full64 || x86_64.scale != 1) {
            auto temp = ctx.reg_allocator().allocate_gpr();
            macro$move_register_masked(*ctx.assembler, temp.gpr(), index.gpr(), x86_64.index.mask,
                                       llir::Register::Mask::Full64, true, false, llir::Extension::SIGN);
            switch (x86_64.scale) {
                case 2:
                    ctx.assembler->sldi(temp.gpr(), index.gpr(), 1);
                    break;
                case 4:
                    ctx.assembler->sldi(temp.gpr(), index.gpr(), 2);
                    break;
                case 8:
                    ctx.assembler->sldi(temp.gpr(), index.gpr(), 3);
                    break;
            }

            index = std::move(temp);
        }
    }

    // Sanity checks
    if (update != llir::MemOp::Update::NONE) {
        // For loads/stores with update, only base should be present and disp should be non-zero
        assert(base);
        assert(!index);
        assert(x86_64.disp);
    }

    // Perform operation depending on available operands
    if (base && index) {
        // Both base and index registers are present
        if (!x86_64.disp) {
            // Optimization: If no displacement is present, used an indexed load/store
            loadstore_indexed(reg, base.gpr(), index.gpr());
        } else {
            // Store base+scaled_index in an intermediate reg and use a displacement load/store
            auto intermediate_reg = ctx.reg_allocator().allocate_gpr();
            ctx.assembler->add(intermediate_reg.gpr(), base.gpr(), index.gpr());

            loadstore_disp_auto(reg, intermediate_reg.gpr(), x86_64.disp);
        }
    } else if (base) {
        // Only base is present - use a displacement load/store
        loadstore_disp_auto(reg, base.gpr(), x86_64.disp);
    } else if (index) {
        // Only index is present - scale it and use a displacement load/store
        loadstore_disp_auto(reg, index.gpr(), x86_64.disp);
    } else {
        // Neither register is present, do a displacement load/store off of the immediate
        loadstore_disp_auto(reg, 0, x86_64.disp);
    }

    // If an update mode is specified, make sure it is written to the actual base register
    if (update != llir::MemOp::Update::NONE) {
        if (orig_base == &base)
            return; // Update already written

        macro$move_register_masked(*ctx.assembler, orig_base->gpr(), base.gpr(), llir::Register::Mask::Full64,
                                   x86_64.base.mask, x86_64.base.zero_others, false);
    }
}

template <typename T>
void codegen_ppc64le<T>::macro$interrupt$trap(gen_context &ctx, runtime_context_ppc64le::NativeTarget target, bool linkage) {
    // To re-enter native code, we just emit a branch to arch_leave_translated_code.
    // Special considerations:
    // * arch_leave_translated code won't save LR for us, so we have to do it
    // * we need to store the target in runtime_context(r11).host_native_context.native_function_call_target
    auto scratch = ctx.reg_allocator().allocate_gpr();

    // Store target
    macro$load_imm(*ctx.assembler, scratch.gpr(), (uint16_t)target, llir::Register::Mask::Full64, true);
    ctx.assembler->std(scratch.gpr(), GPR_FIXED_RUNTIME_CTX, offsetof(runtime_context_ppc64le, native_function_call_target));

    // Load arch_leave_translated_code
    ctx.assembler->ld(scratch.gpr(), GPR_FIXED_RUNTIME_CTX, offsetof(runtime_context_ppc64le, leave_translated_code_ptr));
    ctx.assembler->mtspr(SPR::CTR, scratch.gpr());

    // Save LR
    ctx.assembler->mfspr(scratch.gpr(), SPR::LR);
    ctx.assembler->std(scratch.gpr(), GPR_FIXED_RUNTIME_CTX, TRANSLATED_CTX_OFF(lr));

    // Branch
    if (linkage)
        ctx.assembler->bctrl();
    else
        ctx.assembler->bctr();
}


/**
 * macro_call_native function - Call a native ELFv2 function from translated code
 *
 * Address of native function must be in CTR+r12 before this thunk is executed.
 * Return value of native function (r3) will be put into the first provided gpr argument.
 * All non-volatile ABIRetrec registers must be assumed to be clobbered.
 */
template <typename T>
template <typename... Args>
void codegen_ppc64le<T>::macro$call_native_function(gen_context &ctx, Args... args) {
    static_assert(std::conjunction_v<std::is_convertible<gpr_t, Args>...>, "Arguments must be GPRs");
    static_assert(sizeof...(args) <= ARRAY_SIZE(ABIRetrec<T>::argument_regs));
    assembler &a = *ctx.assembler;

    // Arbitrarily chosen scratch registers that are volatile in RetrecABI and non-volatile in ELFv2
    constexpr auto scratch1 = llir::PPC64Register::R20;
    constexpr auto scratch2 = llir::PPC64Register::R21;
    constexpr gpr_t scratch1_gpr = llir::PPC64RegisterGPRIndex(scratch1);
    constexpr gpr_t scratch2_gpr = llir::PPC64RegisterGPRIndex(scratch2);

    // Assert that the scratch registers are valid according to the ABIs in use
    static_assert(!MAGIC_ARRAY_FIND_OCCURRENCES(ABIRetrec<T>::non_volatile_regs, scratch1));
    static_assert(MAGIC_ARRAY_FIND_OCCURRENCES(ABIElfV2::non_volatile_regs, scratch1));
    static_assert(!MAGIC_ARRAY_FIND_OCCURRENCES(ABIRetrec<T>::non_volatile_regs, scratch2));
    static_assert(MAGIC_ARRAY_FIND_OCCURRENCES(ABIElfV2::non_volatile_regs, scratch2));

    constexpr auto &difference = ABIComparator<ABIRetrec<T>, ABIElfV2>::non_volatile_regs_difference;

    // Preserve old SP in scratch2
    a.mr(scratch2_gpr, GPR_SP);

    // Preserve all registers that are non-volatile in the retrec ABI but volatile in ELFv2
    for (auto reg : difference) {
        // Store the register on the stack using the correct instruction for its type
        switch (llir::PPC64RegisterGetType(reg)) {
            case llir::PPC64RegisterType::GPR:
                a.stdu(llir::PPC64RegisterGPRIndex(reg), GPR_SP, -8);
                break;

            case llir::PPC64RegisterType::SPECIAL:
                if (reg == llir::PPC64Register::CR) {
                    a.mfcr(scratch1_gpr);
                    a.stdu(scratch1_gpr, GPR_SP, -8);
                } else { TODO(); }

                break;

            default:
                TODO();
        }
    }

    // Create an ELFv2 stack frame
    a.addi(1, 1, -32);
    a.addi(scratch1_gpr, 0, 0); // li scratch, 0
    a.std(scratch1_gpr, 1, 0);

    // Write a second backchain pointer if stack is misaligned
    static_assert(magic::array_find_occurrences<difference.size()>(difference, llir::PPC64Register::CR));
    a.andi_(3 /* scratch */, 1, 0xF); // clobbers CR
    a.bc(BO::FIELD_SET, assembler::CR_EQ, 2*4);
    a.stdu(scratch1_gpr, 1, -8);

    // Load parameters
    gpr_t parameters[] = {static_cast<gpr_t>(args)...};
    for (size_t i = 0; i < sizeof...(args); i++) {
        gpr_t cur = parameters[i];
        gpr_t cur_elfv2 = llir::PPC64RegisterGPRIndex(ABIElfV2::argument_regs[i]);

        if (cur != cur_elfv2)
            a.mr(cur_elfv2, cur);
    }

    // Call function (r12, CTR already populated with target)
    a.bctrl();

    // Move result into first parameter
    a.mr(parameters[0], 3);

    // Restore SP and preserved registers
    a.mr(GPR_SP, scratch2_gpr);
    int16_t stack_offset = -8;
    for (auto reg : difference) {
        // Store the register on the stack using the correct instruction for its type
        switch (llir::PPC64RegisterGetType(reg)) {
            case llir::PPC64RegisterType::GPR:
                a.ld(llir::PPC64RegisterGPRIndex(reg), GPR_SP, stack_offset);
                stack_offset += -8;
                break;

            case llir::PPC64RegisterType::SPECIAL:
                if (reg == llir::PPC64Register::CR) {
                    a.ld(scratch1_gpr, GPR_SP, stack_offset);
                    a.mtcr(scratch1_gpr);
                    stack_offset += -8;
                } else { TODO(); }

                break;

            default:
                TODO();
        }
    }
}

template <typename T>
void codegen_ppc64le<T>::macro$nops(ppc64le::assembler &assembler, size_t count) {
    while (count--)
        assembler.nop();
}

template <typename T>
void codegen_ppc64le<T>::macro$nop$relocation(gen_context &ctx, size_t count, relocation &&reloc) {
    assert(count);

    // Emit first nop and attach relocation to it
    ctx.assembler->nop();
    ctx.stream->add_aux(true, std::forward<relocation>(reloc));

    // Emit any extra nops
    macro$nops(*ctx.assembler, count - 1);
}

// Explicitly instantiate for all supported traits
template class retrec::codegen_ppc64le<ppc64le::TargetTraitsX86_64>;
