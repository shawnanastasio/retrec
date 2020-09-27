#pragma once

#include <util.h>
#include <llir.h>
#include <codegen.h>
#include <execution_context.h>
#include <arch/ppc64le/codegen/assembler.h>
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
 *
 * In addition, the following are provided for efficient
 * lazy evaluation of operations that depend on foreign CPU flags (e.g. EFLAGS):
 *     R12 - flag operation operand 1
 *     R13 - flag operation operand 2
 *     R14 - flag operation type
 * Upon any instruction that alters foriegn flags, the operands and operation type
 * will be loaded into R12, R13, and R14 respectively. Then, when generated code
 * needs to evaluate the flags for, e.g. a branch, the values in these registers
 * can be used without the need to access memory.
 *
 * This will hopefully be faster than storing the operation data in the runtime_context
 * and worth wasting 3 registers.
 */
constexpr gpr_t GPR_FIXED_RUNTIME_CTX = 11;
constexpr gpr_t GPR_FIXED_FLAG_OP1 = 12;
constexpr gpr_t GPR_FIXED_FLAG_OP2 = 13;
constexpr gpr_t GPR_FIXED_FLAG_OP_TYPE = 14;

constexpr uint32_t UINT26_MAX = 0x3ffffff; // 2**26 - 1
constexpr int32_t INT26_MAX =   0x1ffffff; // 2**(26-1) - 1
constexpr int32_t INT26_MIN =  -INT26_MAX - 1;

// See above description of R14
enum class LastFlagOp : uint16_t {
    SUB,
};

struct Relocation {
    struct BranchImmUnconditional { uint64_t abs_vaddr; };
    struct BranchImmConditional { assembler::BO bo; uint8_t cr_field; uint64_t abs_vaddr; };

    size_t offset;
    size_t insn_cnt; // Number of instructions reserved for this Relocation
    std::variant<BranchImmUnconditional, BranchImmConditional> data;
};

struct target_traits_x86_64 {
    using RegisterAllocatorT = register_allocator_x86_64;
};

} // namespace ppc64le

template <typename Traits>
class codegen_ppc64le final : public codegen {
    Architecture target;
    execution_context &econtext;
    //typename Traits::RegisterAllocatorT reg_allocator;

    struct gen_context {
        const lifted_llir_block &llir;
        simple_region_writer &code_buffer;
        ppc64le::assembler assembler;

        std::vector<typename Traits::RegisterAllocatorT> reg_allocators;
        typename Traits::RegisterAllocatorT *reg_allocator(const llir::Insn &insn, bool make_new) {
            // Return a register allocator instance that can be used for the given insn
            for (auto &allocator : reg_allocators) {
                if (insn.address >= allocator.start() && (!allocator.end() || insn.address <= allocator.end()))
                    return &allocator;
            }

            if (make_new) {
                // No suitable allocator, create a new one
                log(LOGL_DEBUG, "Creating new register allocator for code at: 0x%llx\n", insn.address);
                reg_allocators.emplace_back((uint64_t)insn.address);
                return &(*(reg_allocators.end() - 1));
            } else
                return nullptr;
        }
        typename Traits::RegisterAllocatorT *reg_allocator(const llir::Insn &insn) { return reg_allocator(insn, true); }

        void invalidate_reg_allocator(const llir::Insn &insn) {
            auto *allocator = reg_allocator(insn, false);
            if (allocator && !allocator->end())
                allocator->set_end(insn.address);
        }

        // Map of (target binary vaddr) : (generated code vaddr) for
        // branch targets
        std::unordered_map<uint64_t, uint64_t> local_branch_targets;

        std::vector<ppc64le::Relocation> relocations;
    };


    static uint64_t resolve_branch_target(const llir::Insn &insn);

    //
    // LLIR code generation functions
    //
    void llir$alu$load_imm(gen_context &ctx, const llir::Insn &insn);
    void llir$alu$sub(gen_context &ctx, const llir::Insn &insn);
    void llir$branch$unconditional(gen_context &ctx, const llir::Insn &insn);
    void llir$branch$conditional(gen_context &ctx, const llir::Insn &insn);
    void llir$interrupt$syscall(gen_context &ctx, const llir::Insn &insn);

    // Dispatch to the appropriate code generation function
    void dispatch(gen_context &ctx, const llir::Insn &insn);

    // Resolve all relocations in a given translation context
    status_code resolve_relocations(gen_context &ctx);

    // Misc. helpers
    static bool rel_off_in_range(int64_t min, int64_t max, uint64_t my_address, uint64_t target) {
        int64_t offset = target - my_address;
        return (offset >= min) && (offset <= max);
    }
    static bool rel26_in_range(uint64_t my_address, uint64_t target) {
        return rel_off_in_range(ppc64le::INT26_MIN, ppc64le::INT26_MAX, my_address, target);
    };
    static bool rel16_in_range(uint64_t my_address, uint64_t target) {
        return rel_off_in_range(INT16_MIN, INT16_MAX, my_address, target);
    };

    //
    // Macro assembler
    //
    void macro$load_imm(ppc64le::assembler &assembler, ppc64le::gpr_t dest, int64_t imm, llir::Register::Mask mask);
    void macro$branch$unconditional(ppc64le::assembler &assembler, uint64_t my_address, uint64_t target, size_t insn_cnt);
    void macro$branch$conditional(ppc64le::assembler &assembler, uint64_t my_address, uint64_t target,
                                  ppc64le::assembler::BO bo, uint8_t cr_field, size_t insn_cnt);
    void macro$mask_register(ppc64le::assembler &assembler, ppc64le::gpr_t reg, llir::Register::Mask mask);

public:
    codegen_ppc64le(Architecture target_, execution_context &econtext_)
        : target(target_), econtext(econtext_)
    {
    }

    status_code init() override;
    status_code translate(const lifted_llir_block& llir, std::optional<translated_code_region> &out) override;
};

}
