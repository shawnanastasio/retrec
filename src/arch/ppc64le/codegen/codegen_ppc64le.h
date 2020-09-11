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
 * Notes on ppc64le JIT ABI:
 *
 * R11 - runtime_context pointer
 * CTR - volatile on native code function calls
 */

constexpr uint32_t UINT26_MAX = 0x3ffffff; // 2**26 - 1
constexpr int32_t INT26_MAX =   0x1ffffff; // 2**(26-1) - 1
constexpr int32_t INT26_MIN =  -INT26_MAX - 1;

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
    typename Traits::RegisterAllocatorT reg_allocator;

    struct gen_context {
        const lifted_llir_block &llir;
        simple_region_writer &code_buffer;
        ppc64le::assembler assembler;

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
    void macro$load_imm(ppc64le::assembler &assembler, ppc64le::gpr_t dest, int64_t imm);
    void macro$branch$unconditional(ppc64le::assembler &assembler, uint64_t my_address, uint64_t target, size_t insn_cnt);
    void macro$branch$conditional(ppc64le::assembler &assembler, uint64_t my_address, uint64_t target,
                                  ppc64le::assembler::BO bo, uint8_t cr_field, size_t insn_cnt);

public:
    codegen_ppc64le(Architecture target_, execution_context &econtext_)
        : target(target_), econtext(econtext_)
    {
    }

    status_code init() override;
    status_code translate(const lifted_llir_block& llir, std::optional<translated_code_region> &out) override;
};

}
