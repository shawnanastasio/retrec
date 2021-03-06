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

#include <util/util.h>
#include <llir.h>
#include <codegen.h>
#include <execution_context.h>
#include <arch/ppc64le/codegen/abi.h>
#include <arch/ppc64le/codegen/codegen_types.h>
#include <arch/ppc64le/codegen/register_allocator.h>
#include <arch/ppc64le/cpu_context_ppc64le.h>
#include <arch/ppc64le/runtime_context_ppc64le.h>
#include <arch/x86_64/cpu_context_x86_64.h>

#include <unordered_map>
#include <variant>
#include <memory>

namespace retrec {

namespace ppc64le {

/**
 * Notes on x86_64 target JIT ABI:
 *
 * R11 - runtime_context pointer
 * CTR - volatile on native code function calls
 * CR0 - Flags generated by Rc=1 instructions (add. and friends)
 * CR1 - Lazily evaluated flags
 *     CR1[2] - CARRY
 *     CR1[3] - OVERFLOW
 * CR2 - Whether the lazy flags in CR1,X are valid or whether they need to be recalculated
 *     CR2[0] - Carry valid
 *     CR2[1] - Overflow valid
 * CR3 - Non-evaluated flags, misc
 *     CR3[0] - Direction flag
 * CR4 - Scratch. Potentially used by lazy evaluation routines.
 * CR7 - Reserved all zeros
 *
 * In addition, the following are provided for efficient
 * lazy evaluation of operations that depend on foreign CPU flags (e.g. EFLAGS):
 *     R14 - flag operation operand 1
 *     R15 - flag operation operand 2
 *     R16 - flag operation result
 *     R17 - flag operation data (See LastFlagOpData for fields)
 * Upon any instruction that alters foriegn flags, the operands and operation type
 * will be loaded into R12, R13, and R14 respectively. Then, when generated code
 * needs to evaluate the flags for, e.g. a branch, the values in these registers
 * can be used without the need to access memory.
 *
 * This will hopefully be faster than storing the operation data in the runtime_context
 * and worth wasting 3 registers.
 */
constexpr uint32_t CR_LAZY = 1; // CR1
constexpr uint32_t CR_LAZY_FIELD_OVERFLOW = CR_LAZY*4 + 3;
constexpr uint32_t CR_LAZY_FIELD_CARRY = CR_LAZY*4 + 2;

constexpr uint32_t CR_LAZYVALID = 2; // CR2
constexpr uint32_t CR_LAZYVALID_CARRY = CR_LAZYVALID*4 + 0; // CR2[0]
constexpr uint32_t CR_LAZYVALID_OVERFLOW = CR_LAZYVALID*4 + 1; // CR2[1]

constexpr uint32_t CR_MISCFLAGS = 3; // CR3
constexpr uint32_t CR_MISCFLAGS_FIELD_DIRECTION = CR_MISCFLAGS*4 + 0; // CR3[0]

constexpr uint32_t CR_SCRATCH = 4; // CR4
constexpr uint32_t CR_ZEROS = 7; // CR7

constexpr uint32_t UINT26_MAX = 0x3ffffff; // 2**26 - 1
constexpr int32_t INT26_MAX =   0x1ffffff; // 2**(26-1) - 1
constexpr int32_t INT26_MIN =  -INT26_MAX - 1;

// See above description of R14
enum class LastFlagOpData : uint32_t {
    // Shift for carry flag calculation (5:0)
    CARRY_ADDSUB_8BIT = 64 - 8,
    CARRY_ADDSUB_16BIT = 64 - 16,
    CARRY_ADDSUB_32BIT = 64 - 32,
    CARRY_DOUBLEWORD_ADD = 62,
    CARRY_DOUBLEWORD_SUB = 63,

    // Shift for overflow flag calculation (11:6)
    OVERFLOW_SHIFT = 6,
    OVERFLOW_BYTE = (57 << OVERFLOW_SHIFT),
    OVERFLOW_HALFWORD = (49 << OVERFLOW_SHIFT),
    OVERFLOW_WORD = (33 << OVERFLOW_SHIFT),
    OVERFLOW_DOUBLEWORD = (1 << OVERFLOW_SHIFT),

    // Jump table for IMUL overflow calculation (1:0)
    IMUL_OVERFLOW_8BIT  = 0,
    IMUL_OVERFLOW_16BIT = 1,
    IMUL_OVERFLOW_32BIT = 2,
    IMUL_OVERFLOW_64BIT = 3,

    // Offset for shift_carry calculation (6:0)
    SHIFT_OFFSET_8BIT = 56,
    SHIFT_OFFSET_16BIT = 48,
    SHIFT_OFFSET_32BIT = 32,
    SHIFT_OFFSET_64BIT = 0,

    // Operation type for flag calculation (15:12)
    OP_TYPE_SHIFT = 12,
    OP_SUB  = (0 << OP_TYPE_SHIFT),
    OP_ADD  = (1 << OP_TYPE_SHIFT),
    OP_IMUL = (2 << OP_TYPE_SHIFT),
    OP_MUL  = (3 << OP_TYPE_SHIFT),
    OP_SHR  = (5 << OP_TYPE_SHIFT),
    OP_SHL  = (6 << OP_TYPE_SHIFT),
    OP_SAR  = (7 << OP_TYPE_SHIFT),
};
enum class LastFlagOp : uint32_t {
    SUB,
    ADD,
    IMUL,
    MUL,
    SHL,
    SHR,
    SAR,
    INVALID
};

} // namespace ppc64le

template <typename Traits>
class codegen_ppc64le final : public codegen {
    Architecture target;
    execution_context &econtext;
    virtual_address_mapper *vam;

    /**
     * Addresses of functions emitted to fixed function table
     */
    struct fixed_function_addresses {
        uint32_t enter_translated_code;
        uint32_t leave_translated_code;
        uint32_t call;
        uint32_t call_direct;
        uint32_t call_direct_rel;
        uint32_t indirect_jmp;
        uint32_t jmp_direct_rel;
        uint32_t syscall;
        uint32_t trap_patch_call;
        uint32_t trap_patch_jump;
        uint32_t imul_overflow;
        uint32_t shift_carry;
        uint32_t shift_overflow;
        uint32_t cpuid;
        uint32_t mul_overflow;
    } ff_addresses;

    /**
     * All codegen state used in translation of a single code block
     */
    struct gen_context {
        std::unique_ptr<ppc64le::assembler> assembler;
        std::unique_ptr<ppc64le::instruction_stream> stream;
        ppc64le::register_allocator<Traits> m_reg_allocator;
        // Map of (target binary vaddr) : (instruction stream offset) for branch targets
        std::unordered_map<uint64_t, size_t> local_branch_targets;
        virtual_address_mapper *vam;

        gen_context(virtual_address_mapper *);
        ~gen_context();

        auto &reg_allocator() { return m_reg_allocator; }
    };

    void write_function_map(gen_context &ctx, uint64_t output_haddr);

    static uint64_t resolve_branch_target(const llir::Insn &insn);

    // All ALU flags that are stored in Rc=0 (i.e. not lazily evaluated)
    static constexpr llir::Alu::FlagArr llir$alu$all_rc0_flags = {llir::Alu::Flag::SIGN, llir::Alu::Flag::ZERO};
    static constexpr llir::Alu::FlagArr llir$alu$all_lazy_flags = {llir::Alu::Flag::CARRY, llir::Alu::Flag::OVERFLOW};

    // Import register aliases from the ABI
    static constexpr auto GPR_SP = ppc64le::ABIRetrec<Traits>::GPR_SP;
    static constexpr auto GPR_FIXED_RUNTIME_CTX = ppc64le::ABIRetrec<Traits>::GPR_FIXED_RUNTIME_CTX;
    static constexpr auto GPR_FIXED_FLAG_OP1 = ppc64le::ABIRetrec<Traits>::GPR_FIXED_FLAG_OP1;
    static constexpr auto GPR_FIXED_FLAG_OP2 = ppc64le::ABIRetrec<Traits>::GPR_FIXED_FLAG_OP2;
    static constexpr auto GPR_FIXED_FLAG_RES = ppc64le::ABIRetrec<Traits>::GPR_FIXED_FLAG_RES;
    static constexpr auto GPR_FIXED_FLAG_OP_TYPE = ppc64le::ABIRetrec<Traits>::GPR_FIXED_FLAG_OP_TYPE;

    // The number of instructions needed to patch in a direct branch with and without linkage, respectively.
    // This accounts for 2 instructions to load a 32-bit immediate code buffer address and 1 bla to a fixed
    // function helper.
    //
    // In the future if we support a larger memory model with code buffers out of the 32-bit address space,
    // these will have to be updated along with the corresponding relocation/patch code.
    static constexpr size_t DIRECT_CALL_PATCH_INSN_COUNT = 3;
    static constexpr size_t DIRECT_JMP_PATCH_INSN_COUNT = 3;

    struct pcrel_branch_patch_offsets {
        size_t imm_insn_count;     // Amount of instructions required to load original immediate
        size_t new_imm_insn_count; // Amount of instructions required to load immediate after subtracting PCrel offset
        size_t new_offset;         // New target with subtracted PCrel offset
        size_t middle_nops;        // Amount of NOPs required between load_imm and bla
        size_t end_nops;           // Amount of NOPs required after bla
    };

    // Helper for calculating offsets for a PC-relative branch patch
    pcrel_branch_patch_offsets calculate_pcrel_branch_patch_offsets(size_t patch_insn_count, int64_t target_off);

    //
    // LLIR code generation functions
    //

    /* ALU */
    llir::Register::Mask llir$alu$helper$target_mask(llir::Register::Mask src_mask);
    llir::Register::Mask llir$alu$helper$mask_from_width(llir::Operand::Width w);
    void llir$alu$helper$load_operand_into_gpr(gen_context &ctx, const llir::Insn &insn, const llir::Operand &op,
                                               ppc64le::gpr_t target, llir::Extension extension = llir::Extension::ZERO);
    void llir$alu$helper$finalize_op(gen_context &ctx, const llir::Insn &insn, ppc64le::LastFlagOp op);
    llir::Alu::FlagArr llir$alu$helper$preserve_flags(gen_context &ctx, const llir::Insn &insn);
    void llir$alu$helper$restore_flags(gen_context &ctx, llir::Alu::FlagArr &flags);
    size_t llir$alu$helper$load_imm_insn_count(int64_t val);
    ppc64le::LastFlagOp llir$alu$helper$insn_to_lastflagop(const llir::Insn &insn);

    void llir$alu$load_imm(gen_context &ctx, const llir::Insn &insn);
    void llir$alu$2src_common(gen_context &ctx, const llir::Insn &insn);
    void llir$alu$move_reg(gen_context &ctx, const llir::Insn &insn);
    void llir$alu$move_vector_reg(gen_context &ctx, const llir::Insn &insn);
    void llir$alu$setcc(gen_context &ctx, const llir::Insn &insn);
    void llir$alu$setclrflag(gen_context &ctx, const llir::Insn &insn);
    void llir$alu$x86_cpuid(gen_context &ctx, const llir::Insn &insn);

    /* Branch */
    ppc64le::BO llir$branch$helper$invert_bo(ppc64le::BO bo);
    void llir$branch$helper$evaluate_op(gen_context &ctx, llir::Branch::Op op, uint8_t *cr_field_out, ppc64le::BO *bo_out);

    void llir$branch$unconditional(gen_context &ctx, const llir::Insn &insn);
    void llir$branch$conditional(gen_context &ctx, const llir::Insn &insn);

    /* Interrupt */
    void llir$interrupt$syscall(gen_context &ctx, const llir::Insn &insn);

    /* Load/Store */
    void llir$loadstore(gen_context &ctx, const llir::Insn &insn);
    void llir$loadstore_float(gen_context &ctx, const llir::Insn &insn);

    // Dispatch to the appropriate code generation function
    void dispatch(gen_context &ctx, const llir::Insn &insn);

    // Emit the end-of-block epilogue
    void emit_epilogue(gen_context &ctx, const lifted_llir_block &llir);

    //
    // Fixed helper functions - Emitted once per process in the function table
    //
    void fixed_helper$enter_translated_code$emit(gen_context &ctx);
    void fixed_helper$leave_translated_code$emit(gen_context &ctx);
    void fixed_helper$call$emit(gen_context &ctx);
    void fixed_helper$call_direct$emit(gen_context &ctx, bool rel);
    void fixed_helper$indirect_jmp$emit(gen_context &ctx);
    void fixed_helper$jmp_direct_rel$emit(gen_context &ctx);
    void fixed_helper$syscall$emit(gen_context &ctx);
    void fixed_helper$trap_patch_call$emit(gen_context &ctx);
    void fixed_helper$trap_patch_jump$emit(gen_context &ctx);
    void fixed_helper$imul_overflow$emit(gen_context &ctx);
    void fixed_helper$shift_carry$emit(gen_context &ctx);
    void fixed_helper$shift_overflow$emit(gen_context &ctx);
    void fixed_helper$cpuid$emit(gen_context &ctx);
    void fixed_helper$mul_overflow$emit(gen_context &ctx);

    // Resolve all relocations in a given translation context
    status_code resolve_relocations(gen_context &ctx);

    // Misc. helpers
    static bool rel_off_in_range(int64_t min, int64_t max, uint64_t my_address, uint64_t target) {
        int64_t offset = (int64_t)(target - my_address);
        return (offset >= min) && (offset <= max);
    }
    static bool rel26_in_range(uint64_t my_address, uint64_t target) {
        return rel_off_in_range(ppc64le::INT26_MIN, ppc64le::INT26_MAX, my_address, target);
    }
    static bool rel16_in_range(uint64_t my_address, uint64_t target) {
        return rel_off_in_range(INT16_MIN, INT16_MAX, my_address, target);
    }

    llir::Operand::Width mask_to_width(llir::Register::Mask mask) {
        switch (mask) {
            case llir::Register::Mask::Full64: return llir::Operand::Width::_64BIT;
            case llir::Register::Mask::Low32: return llir::Operand::Width::_32BIT;
            case llir::Register::Mask::LowLow16: return llir::Operand::Width::_16BIT;
            case llir::Register::Mask::LowLowHigh8:
            case llir::Register::Mask::LowLowLow8:
                return llir::Operand::Width::_8BIT;
            default:
                ASSERT_NOT_REACHED();
        }
    }

    /**
     * Small helper to determine if a given int64_t immediate can be losslessly converted
     * into integral type `T`.
     */
    template <typename T>
    bool imm_fits_in(int64_t imm) {
        return static_cast<T>(imm) == imm;
    }

    static inline uint32_t build_flag_op_data(ppc64le::LastFlagOp op, llir::Register::Mask mask) {
        uint32_t data = 0;

        switch (op) {
            case ppc64le::LastFlagOp::ADD: data |= enum_cast(ppc64le::LastFlagOpData::OP_ADD); goto addsub_common;
            case ppc64le::LastFlagOp::SUB: data |= enum_cast(ppc64le::LastFlagOpData::OP_SUB); goto addsub_common;
            addsub_common:
                switch (mask) {
                    case llir::Register::Mask::Full64:
                        data |= (op == ppc64le::LastFlagOp::ADD ? enum_cast(ppc64le::LastFlagOpData::CARRY_DOUBLEWORD_ADD)
                                    : enum_cast(ppc64le::LastFlagOpData::CARRY_DOUBLEWORD_SUB));
                        data |= enum_cast(ppc64le::LastFlagOpData::OVERFLOW_DOUBLEWORD);
                        break;
                    case llir::Register::Mask::Low32:
                        data |= enum_cast(ppc64le::LastFlagOpData::CARRY_ADDSUB_32BIT);
                        data |= enum_cast(ppc64le::LastFlagOpData::OVERFLOW_WORD);
                        break;
                    case llir::Register::Mask::LowLow16:
                        data |= enum_cast(ppc64le::LastFlagOpData::CARRY_ADDSUB_16BIT);
                        data |= enum_cast(ppc64le::LastFlagOpData::OVERFLOW_HALFWORD);
                        break;
                    case llir::Register::Mask::LowLowHigh8:
                    case llir::Register::Mask::LowLowLow8:
                        data |= enum_cast(ppc64le::LastFlagOpData::CARRY_ADDSUB_8BIT);
                        data |= enum_cast(ppc64le::LastFlagOpData::OVERFLOW_BYTE);
                        break;
                    default:
                        ASSERT_NOT_REACHED();
                }
                break;

            case ppc64le::LastFlagOp::MUL:  data |= enum_cast(ppc64le::LastFlagOpData::OP_MUL); goto mul_common;
            case ppc64le::LastFlagOp::IMUL: data |= enum_cast(ppc64le::LastFlagOpData::OP_IMUL); goto mul_common;
            mul_common:
                switch (mask) {
                    case llir::Register::Mask::Full64:
                        data |= enum_cast(ppc64le::LastFlagOpData::IMUL_OVERFLOW_64BIT);
                        break;
                    case llir::Register::Mask::Low32:
                        data |= enum_cast(ppc64le::LastFlagOpData::IMUL_OVERFLOW_32BIT);
                        break;
                    case llir::Register::Mask::LowLow16:
                        data |= enum_cast(ppc64le::LastFlagOpData::IMUL_OVERFLOW_16BIT);
                        break;
                    case llir::Register::Mask::LowLowHigh8:
                    case llir::Register::Mask::LowLowLow8:
                        data |= enum_cast(ppc64le::LastFlagOpData::IMUL_OVERFLOW_8BIT);
                        break;
                    default:
                        ASSERT_NOT_REACHED();
                }
                break;

            case ppc64le::LastFlagOp::SHL:
                data |= enum_cast(ppc64le::LastFlagOpData::OP_SHL);
                goto shift_common;
            case ppc64le::LastFlagOp::SHR:
                data |= enum_cast(ppc64le::LastFlagOpData::OP_SHR);
                goto shift_common;
            case ppc64le::LastFlagOp::SAR:
                data |= enum_cast(ppc64le::LastFlagOpData::OP_SAR);
                goto shift_common;
            shift_common:
                switch (mask) {
                    case llir::Register::Mask::Full64:
                        data |= enum_cast(ppc64le::LastFlagOpData::SHIFT_OFFSET_64BIT);
                        break;
                    case llir::Register::Mask::Low32:
                        data |= enum_cast(ppc64le::LastFlagOpData::SHIFT_OFFSET_32BIT);
                        break;
                    case llir::Register::Mask::LowLow16:
                        data |= enum_cast(ppc64le::LastFlagOpData::SHIFT_OFFSET_16BIT);
                        break;
                    case llir::Register::Mask::LowLowHigh8:
                    case llir::Register::Mask::LowLowLow8:
                        data |= enum_cast(ppc64le::LastFlagOpData::SHIFT_OFFSET_8BIT);
                        break;
                    default:
                        ASSERT_NOT_REACHED();
                }
                break;

            default:
                TODO();
        }

        return data;
    }

    //
    // Macro assembler
    //
    void macro$load_imm(ppc64le::assembler &assembler, ppc64le::gpr_t dest, int64_t imm, llir::Register::Mask mask,
                        bool zero_others);
    void macro$alu$add_imm(gen_context &ctx, ppc64le::gpr_t dest, int64_t imm);
    void macro$branch$unconditional(ppc64le::assembler &assembler, uint64_t my_address, uint64_t target, size_t insn_cnt);
    void macro$branch$conditional(ppc64le::assembler &assembler, uint64_t my_address, uint64_t target,
                                  ppc64le::BO bo, uint8_t cr_field, size_t insn_cnt);
    void macro$branch$conditional$carry(gen_context &ctx);
    void macro$branch$conditional$overflow(gen_context &ctx);
    void macro$mask_register(ppc64le::assembler &assembler, ppc64le::gpr_t dest, ppc64le::gpr_t src, llir::Register::Mask mask,
                             bool invert, bool modify_cr);
    void macro$move_register_masked(ppc64le::assembler &assembler, ppc64le::gpr_t dest, ppc64le::gpr_t src,
                                    llir::Register::Mask src_mask, llir::Register::Mask dest_mask, bool zero_others,
                                    bool modify_cr, llir::Extension extension = llir::Extension::ZERO);
    void macro$loadstore(gen_context &ctx, const llir::Register &reg, const llir::Operand &mem_op, const llir::Insn &insn,
                         const llir::LoadStore &loadstore);
    void macro$loadstore_gpr(gen_context &ctx, ppc64le::gpr_t reg, const llir::Operand &mem_op, llir::LoadStore::Op,
                             llir::Register::Mask reg_mask, bool reg_zero_others, const llir::Insn &insn,
                             llir::Extension extension = llir::Extension::NONE);
    void macro$interrupt$trap(gen_context &ctx, runtime_context_ppc64le::NativeTarget target, bool linkage = true);
    template <typename... Args> void macro$call_native_function(gen_context &ctx, Args... args);
    void macro$nops(ppc64le::assembler &assembler, size_t count);
    void macro$nop$relocation(gen_context &ctx, size_t count, ppc64le::relocation &&reloc);

public:
    codegen_ppc64le(Architecture target_, execution_context &econtext_, virtual_address_mapper *vam_)
        : target(target_), econtext(econtext_), vam(vam_)
    {
    }

    status_code init() override;
    status_code translate(const lifted_llir_block& llir, std::optional<translated_code_region> &out) override;
    uint64_t get_last_untranslated_access(void *rctx_) override;
    status_code patch_translated_access(void *rctx_, uint64_t resolved_haddr) override;
};

static inline std::unique_ptr<codegen> make_codegen_ppc64le(Architecture target_arch,
                                                            execution_context &econtext,
                                                            virtual_address_mapper *vam) {
    switch (target_arch) {
        case Architecture::X86_64:
            return std::unique_ptr<codegen>{ new codegen_ppc64le<ppc64le::TargetTraitsX86_64>(target_arch, econtext, vam) };
        default:
            TODO();
    }
}

}
