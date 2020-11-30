#pragma once

#include <util/util.h>
#include <llir.h>
#include <codegen.h>
#include <execution_context.h>
#include <arch/ppc64le/codegen/codegen_types.h>
#include <arch/ppc64le/codegen/register_allocator.h>
#include <arch/ppc64le/cpu_context_ppc64le.h>
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
 * CR2 - Other lazily evaluated flags
 *     CR2[2] - CARRY
 *     CR2[3] - OVERFLOW
 * CR4 - Whether the lazy flags in CR1,X are valid or whether they need to be recalculated
 *     CR4[0] - Carry valid
 *     CR4[1] - Overflow valid
 * CR5 - Scratch. Potentially used by lazy evaluation routines.
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
constexpr gpr_t GPR_FIXED_RUNTIME_CTX = 11;
constexpr gpr_t GPR_FIXED_FLAG_OP1 = 14;
constexpr gpr_t GPR_FIXED_FLAG_OP2 = 15;
constexpr gpr_t GPR_FIXED_FLAG_RES = 16;
constexpr gpr_t GPR_FIXED_FLAG_OP_TYPE = 17;

constexpr uint32_t CR_LAZY = 1; // CR1
constexpr uint32_t CR_LAZY_FIELD_OVERFLOW = CR_LAZY*4 + 3;
constexpr uint32_t CR_LAZY_FIELD_CARRY = CR_LAZY*4 + 2;

constexpr uint32_t CR_LAZYVALID = 2; // CR2
constexpr uint32_t CR_LAZYVALID_CARRY = CR_LAZYVALID*4 + 0; // CR2[0]
constexpr uint32_t CR_LAZYVALID_OVERFLOW = CR_LAZYVALID*4 + 1; // CR2[1]

constexpr uint32_t CR_SCRATCH = 3; // CR3
constexpr uint32_t CR_ZEROS = 7; // CR7

constexpr uint32_t UINT26_MAX = 0x3ffffff; // 2**26 - 1
constexpr int32_t INT26_MAX =   0x1ffffff; // 2**(26-1) - 1
constexpr int32_t INT26_MIN =  -INT26_MAX - 1;

// See above description of R14
enum class LastFlagOpData : uint32_t {
    // Jump table for carry flag calculation
    CARRY_BYTE = 3*4,
    CARRY_HALFWORD = 5*4,
    CARRY_WORD = 7*4,
    CARRY_DOUBLEWORD_ADD = 9*4,
    CARRY_DOUBLEWORD_SUB = 12*4,

    // Shift for overflow flag calculation (13:8)
    OVERFLOW_SHIFT = 8,
    OVERFLOW_BYTE = (57 << OVERFLOW_SHIFT),
    OVERFLOW_HALFWORD = (49 << OVERFLOW_SHIFT),
    OVERFLOW_WORD = (33 << OVERFLOW_SHIFT),
    OVERFLOW_DOUBLEWORD = (1 << OVERFLOW_SHIFT),

    // Operation type for flag calculation (15:14)
    OP_TYPE_SHIFT = 14,
    OP_SUB = (0 << OP_TYPE_SHIFT),
    OP_ADD = (1 << OP_TYPE_SHIFT),
};
enum class LastFlagOp : uint32_t {
    SUB = (0 << 8),
    ADD = (1 << 8),
};

struct target_traits_x86_64 {
    using RegisterAllocatorT = register_allocator_x86_64;
};

} // namespace ppc64le

template <typename Traits>
class codegen_ppc64le final : public codegen {
    Architecture target;
    execution_context &econtext;

    /**
     * All codegen state used in translation of a single code block
     */
    struct gen_context {
        const lifted_llir_block &llir;
        std::unique_ptr<ppc64le::assembler> assembler;
        std::unique_ptr<ppc64le::instruction_stream> stream;
        typename Traits::RegisterAllocatorT m_reg_allocator;

        // Map of (target binary vaddr) : (instruction stream offset) for branch targets
        std::unordered_map<uint64_t, size_t> local_branch_targets;

        gen_context(const lifted_llir_block &llir_);

        auto &reg_allocator() { return m_reg_allocator; }
    };

    static uint64_t resolve_branch_target(const llir::Insn &insn);

    // All ALU flags that are stored in Rc=0 (i.e. not lazily evaluated)
    static constexpr llir::Alu::FlagArr llir$alu$all_rc0_flags = { llir::Alu::Flag::SIGN, llir::Alu::Flag::ZERO };

    //
    // LLIR code generation functions
    //

    /* ALU */
    llir::Register::Mask llir$alu$helper$target_mask(llir::Register::Mask src_mask);
    llir::Register::Mask llir$alu$helper$mask_from_width(llir::Operand::Width w);
    void llir$alu$helper$load_operand_into_gpr(gen_context &ctx, const llir::Operand &op, ppc64le::gpr_t target);
    void llir$alu$helper$finalize_op(gen_context &ctx, const llir::Insn &insn, ppc64le::LastFlagOp op);
    llir::Alu::FlagArr llir$alu$helper$preserve_flags(gen_context &ctx, const llir::Insn &insn);
    void llir$alu$helper$restore_flags(gen_context &ctx, llir::Alu::FlagArr &flags);

    void llir$alu$load_imm(gen_context &ctx, const llir::Insn &insn);
    void llir$alu$sub(gen_context &ctx, const llir::Insn &insn);
    void llir$alu$add(gen_context &ctx, const llir::Insn &insn);

    /* Branch */
    void llir$branch$unconditional(gen_context &ctx, const llir::Insn &insn);
    void llir$branch$conditional(gen_context &ctx, const llir::Insn &insn);

    /* Interrupt */
    void llir$interrupt$syscall(gen_context &ctx, const llir::Insn &insn);

    /* Load/Store */
    void llir$loadstore(gen_context &ctx, const llir::Insn &insn);

    // Dispatch to the appropriate code generation function
    void dispatch(gen_context &ctx, const llir::Insn &insn);

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

    static inline uint16_t build_flag_op_data(ppc64le::LastFlagOp op, llir::Register::Mask mask) {
        ppc64le::LastFlagOpData data;

        switch (mask) {
            case llir::Register::Mask::Full64:
                if (op == ppc64le::LastFlagOp::SUB)
                    data = (ppc64le::LastFlagOpData)((uint32_t)ppc64le::LastFlagOpData::CARRY_DOUBLEWORD_SUB
                           | (uint32_t)ppc64le::LastFlagOpData::OVERFLOW_DOUBLEWORD);
                else if (op == ppc64le::LastFlagOp::ADD)
                    data = (ppc64le::LastFlagOpData)((uint32_t)ppc64le::LastFlagOpData::CARRY_DOUBLEWORD_ADD
                           | (uint32_t)ppc64le::LastFlagOpData::OVERFLOW_DOUBLEWORD);
                else
                    TODO();

                break;
            case llir::Register::Mask::Low32:
                data = (ppc64le::LastFlagOpData)((uint32_t)ppc64le::LastFlagOpData::CARRY_WORD
                       | (uint32_t)ppc64le::LastFlagOpData::OVERFLOW_WORD);
                break;
            case llir::Register::Mask::LowLow16:
                data = (ppc64le::LastFlagOpData)((uint32_t)ppc64le::LastFlagOpData::CARRY_HALFWORD
                       | (uint32_t)ppc64le::LastFlagOpData::OVERFLOW_HALFWORD);
                break;
            case llir::Register::Mask::LowLowLow8:
            case llir::Register::Mask::LowLowHigh8:
                data = (ppc64le::LastFlagOpData)((uint32_t)ppc64le::LastFlagOpData::CARRY_BYTE
                       | (uint32_t)ppc64le::LastFlagOpData::OVERFLOW_BYTE);
                break;
            default: TODO();
        }

        // Fill in operation type
        if (op == ppc64le::LastFlagOp::SUB)
            data = (ppc64le::LastFlagOpData)((uint32_t)data | (uint32_t)ppc64le::LastFlagOpData::OP_SUB);
        else if (op == ppc64le::LastFlagOp::ADD)
            data = (ppc64le::LastFlagOpData)((uint32_t)data | (uint32_t)ppc64le::LastFlagOpData::OP_ADD);
        else
            TODO();

        return (uint16_t)data;
    }

    //
    // Macro assembler
    //
    void macro$load_imm(ppc64le::assembler &assembler, ppc64le::gpr_t dest, int64_t imm, llir::Register::Mask mask,
                        bool zero_others);
    void macro$branch$unconditional(ppc64le::assembler &assembler, uint64_t my_address, uint64_t target, size_t insn_cnt);
    void macro$branch$conditional(ppc64le::assembler &assembler, uint64_t my_address, uint64_t target,
                                  ppc64le::BO bo, uint8_t cr_field, size_t insn_cnt);
    void macro$branch$conditional$carry(gen_context &ctx);
    void macro$branch$conditional$overflow(gen_context &ctx);
    void macro$mask_register(ppc64le::assembler &assembler, ppc64le::gpr_t dest, ppc64le::gpr_t src, llir::Register::Mask mask,
                             bool invert, bool modify_cr);
    void macro$move_register_masked(ppc64le::assembler &assembler, ppc64le::gpr_t dest, ppc64le::gpr_t src,
                                    llir::Register::Mask src_mask, llir::Register::Mask dest_mask, bool zero_others, bool modify_cr);
    void macro$loadstore(gen_context &ctx, ppc64le::gpr_t reg, const llir::MemOp &mem, llir::LoadStore::Op op,
                         llir::Register::Mask reg_mask);

public:
    codegen_ppc64le(Architecture target_, execution_context &econtext_)
        : target(target_), econtext(econtext_)
    {
    }

    status_code init() override;
    status_code translate(const lifted_llir_block& llir, std::optional<translated_code_region> &out) override;
};

}
