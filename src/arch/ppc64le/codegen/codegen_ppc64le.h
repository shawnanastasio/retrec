#pragma once

#include <util.h>
#include <llir.h>
#include <codegen.h>
#include <execution_context.h>
#include <arch/ppc64le/codegen/assembler.h>
#include <arch/ppc64le/cpu_context_ppc64le.h>
#include <arch/x86_64/cpu_context_x86_64.h>

#include <unordered_map>
#include <memory>

namespace retrec {

namespace ppc64le {

using gpr_t = uint8_t;
static constexpr gpr_t GPR_INVALID = (gpr_t)-1;

/**
 * Notes on ppc64le JIT ABI:
 *
 * R11 - runtime_context pointer
 * CTR - volatile on native code function calls
 */

/**
 * Register allocator for X86_64 targets
 */
class register_allocator_x86_64 {
    // Allocation status of GPRs. True = reserved, false = free.
    struct RegisterInfo {
        enum class State {
            FREE,
            ALLOCATED,
            RESERVED
        } state;
    } gprs[32];

    // Statically allocated GPRs.
    gpr_t reserved_allocations[(size_t)llir::X86_64Register::MAXIMUM - 1];

    bool is_reserved(gpr_t gpr) {
        for (size_t i=0; i<ARRAY_SIZE(reserved_allocations); i++)
            if (reserved_allocations[i] == gpr)
                return true;
        return false;
    }

    // reserved_allocations doesn't reserve space for the invalid register index 0, so subtract 1 to get index
    size_t reserved_index(const llir::Register &reg) { return (size_t)reg.x86_64 - 1; }
    size_t reserved_index(llir::X86_64Register reg) { return (size_t)reg - 1; }

public:
    register_allocator_x86_64() {
        for (size_t i=0; i<ARRAY_SIZE(gprs); i++)
            gprs[i] = { RegisterInfo::State::FREE };

        for (size_t i=0; i<ARRAY_SIZE(reserved_allocations); i++)
            reserved_allocations[i] = GPR_INVALID;

        // Statically allocate some X86_64 registers to GPRs.
        // The static allocations try to match X86_64 SysV calling conventions
        // to ppc64le ELFv2 calling conventions to reduce the save/restore penalty when
        // foreign function calls or syscalls are made.
        //
        // Must be kept in sync with accessors in runtime_context_ppc64le.h
        reserved_allocations[reserved_index(llir::X86_64Register::RDI)] = 3; gprs[3] = {RegisterInfo::State::RESERVED};
        reserved_allocations[reserved_index(llir::X86_64Register::RSI)] = 4; gprs[4] = {RegisterInfo::State::RESERVED};
        reserved_allocations[reserved_index(llir::X86_64Register::RDX)] = 5; gprs[5] = {RegisterInfo::State::RESERVED};
        reserved_allocations[reserved_index(llir::X86_64Register::RCX)] = 6; gprs[6] = {RegisterInfo::State::RESERVED};
        reserved_allocations[reserved_index(llir::X86_64Register::R8)]  = 7; gprs[7] = {RegisterInfo::State::RESERVED};
        reserved_allocations[reserved_index(llir::X86_64Register::R9)]  = 8; gprs[8] = {RegisterInfo::State::RESERVED};
        reserved_allocations[reserved_index(llir::X86_64Register::RAX)] = 9; gprs[9] = {RegisterInfo::State::RESERVED};

        // Store pointer to runtime_context in R11
        gprs[11] = {RegisterInfo::State::RESERVED};
    }

    /// Allocate a register for a given target register, with optional value hint
    gpr_t allocate_gpr_internal(const llir::Register *reg, const int64_t *hint) {
        if (reg) {
            // Check if this register has a reserved static allocation
            gpr_t reserved = reserved_allocations[reserved_index(*reg)];
            if (reserved != GPR_INVALID)
                return reserved;
        }

        // No stipulations
        for (gpr_t i=1 /* skip GPR0 which is sometimes useless */; i<ARRAY_SIZE(gprs); i++) {
            if (gprs[i].state == RegisterInfo::State::FREE) {
                gprs[i].state = RegisterInfo::State::ALLOCATED;
                return i;
            }
        }

        return GPR_INVALID; // No free registers
    }
    gpr_t allocate_gpr(const llir::Register &reg) { return allocate_gpr_internal(&reg, nullptr); }
    gpr_t allocate_gpr() { return allocate_gpr_internal(nullptr, nullptr); }

    void free_gpr(gpr_t gpr) {
        assert(gpr != GPR_INVALID);
        assert(gprs[gpr].state == RegisterInfo::State::ALLOCATED);
        gprs[gpr].state = RegisterInfo::State::FREE;
    }
};

struct Relocation {
    size_t offset;
    enum class Type {
        BRANCH_REL24
    } type;
    int64_t data;
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


    static int64_t resolve_branch_target(const llir::Insn &insn);

    //
    // LLIR code generation functions
    //
    void llir$alu$load_imm(gen_context &ctx, const llir::Insn &insn);
    void llir$branch$unconditional(gen_context &ctx, const llir::Insn &insn);
    void llir$interrupt$syscall(gen_context &ctx, const llir::Insn &insn);

    // Dispatch to the appropriate code generation function
    void dispatch(gen_context &ctx, const llir::Insn &insn);

    // Resolve all relocations in a given translation context
    status_code resolve_relocations(gen_context &ctx);

    //
    // Macro assembler
    //
    void macro$load_imm(ppc64le::assembler &assembler, ppc64le::gpr_t dest, int64_t imm);
    void macro$branch$unconditional(ppc64le::assembler &assembler, uint64_t my_address, uint64_t target);

public:
    explicit codegen_ppc64le(Architecture target_, execution_context &econtext_)
        : target(target_), econtext(econtext_)
    {
    }

    status_code init() override;
    status_code translate(const lifted_llir_block& llir, std::optional<translated_code_region> &out) override;
};

}