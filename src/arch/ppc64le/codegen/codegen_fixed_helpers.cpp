/**
 * Copyright 2021 Shawn Anastasio.
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

/**
 * This file contains codegen routines for emitting "fixed helpers", i.e.
 * routines that are emitted to a fixed location once on startup and are called
 * by generated code throughout the translated process' lifetime.
 */

#include <arch/ppc64le/codegen/codegen_ppc64le.h>
#include <arch/ppc64le/codegen/codegen_ppc64le_internal.h>
#include <arch/ppc64le/codegen/abi.h>
#include <arch/ppc64le/codegen/assembler.h>
#include <arch/x86_64/target_environment.h>

using namespace retrec;
using namespace retrec::ppc64le;

template <typename T>
static void loadstore_context_reg(assembler &a, gpr_t runtime_ctx_reg, llir::PPC64Register reg, bool load_or_store, bool native_or_translated) {
#define get_context_offset(member) \
    (uint16_t)(native_or_translated ? (offsetof(runtime_context_ppc64le, host_native_context.member)) : \
        (offsetof(runtime_context_ppc64le, host_translated_context.member)))

    uint8_t reg_idx;
    switch (llir::PPC64RegisterGetType(reg)) {
        case llir::PPC64RegisterType::GPR:
            reg_idx = llir::PPC64RegisterGPRIndex(reg);
            if (load_or_store)
                a.ld(reg_idx, runtime_ctx_reg, (int16_t)(get_context_offset(gprs) + sizeof(cpu_context_ppc64le::gprs[0]) * reg_idx));
            else
                a.std(reg_idx, runtime_ctx_reg, (int16_t)(get_context_offset(gprs) + sizeof(cpu_context_ppc64le::gprs[0]) * reg_idx));
            break;

        case llir::PPC64RegisterType::FPR:
            reg_idx = llir::PPC64RegisterFPRIndex(reg);
            if (load_or_store)
                a.lfd(reg_idx, runtime_ctx_reg, (int16_t)(get_context_offset(vsr[0]) + (sizeof(cpu_context_ppc64le::vsr[0]) * reg_idx) +
                                                offsetof(reg128, le.lo)));
            else
                a.stfd(reg_idx, runtime_ctx_reg, (int16_t)(get_context_offset(vsr[0]) + (sizeof(cpu_context_ppc64le::vsr[0]) * reg_idx) +
                                                 offsetof(reg128, le.lo)));
            break;

        case llir::PPC64RegisterType::VR:  reg_idx = 32 + llir::PPC64RegisterVRIndex(reg); goto vsr_common;
        case llir::PPC64RegisterType::VSR: reg_idx = llir::PPC64RegisterVSRIndex(reg); goto vsr_common;
        vsr_common:
            if (load_or_store)
                a.lxv(reg_idx, runtime_ctx_reg, (int16_t)(get_context_offset(vsr[0]) + sizeof(cpu_context_ppc64le::vsr[0]) * reg_idx));
            else
                a.stxv(reg_idx, runtime_ctx_reg, (int16_t)(get_context_offset(vsr[0]) + sizeof(cpu_context_ppc64le::vsr[0]) * reg_idx));
            break;

        default:
            TODO();
    }

#undef get_context_offset
}

/**
 * Emit the fixed helper for entering translated code from native ELFv2 code.
 *
 * Routine description:
 * Called from native ELFv2 code to switch contexts into translated code. Accepts a
 * single parameter - a runtime_context_ppc64le pointer in r3.
 *
 * This is the only fixed helper routine that is meant to be called from native ELFv2
 * code rather than translated code.
 *
 * Calling convention:
 *   (runtime_context_ppc64le *) [r3] - Runtime context struct to enter.
 *
 * Note: Only non-volatle registers designated by ABIRetrec will be restored. Any
 * registers marked as volatile by ABIRetrec will not be restored.
 *
 * All registers marked as non-volatile by the ELFv2 ABI will be saved.
 */
template <typename T>
void codegen_ppc64le<T>::fixed_helper$enter_translated_code$emit(gen_context &ctx) {
    auto &a = *ctx.assembler;
    constexpr gpr_t RUNTIME_CTX = 3;

    // Save all ELFv2 non-volatile non-special registers to the host native context
    for (auto reg : ABIElfV2::non_volatile_regs) {
        switch (llir::PPC64RegisterGetType(reg)) {
            case llir::PPC64RegisterType::GPR:
            case llir::PPC64RegisterType::FPR:
            case llir::PPC64RegisterType::VSR:
            case llir::PPC64RegisterType::VR:
                loadstore_context_reg<T>(a, RUNTIME_CTX, reg, false, true);
                break;

            default:
                break;
        }
    }

    // Save LR, CR
    constexpr gpr_t SCRATCH = 4;
    a.mfspr(SCRATCH, SPR::LR);
    a.std(SCRATCH, RUNTIME_CTX, offsetof(runtime_context_ppc64le, host_native_context.lr));
    a.mfcr(SCRATCH);
    a.std(SCRATCH, RUNTIME_CTX, offsetof(runtime_context_ppc64le, host_native_context.cr));

    // Restore all ABIRetrec non-special non-volatile registers from the host translated context
    for (auto reg : ABIRetrec<T>::non_volatile_regs) {
        switch (llir::PPC64RegisterGetType(reg)) {
            case llir::PPC64RegisterType::GPR:
            {
                // Don't restore the SCRATCH or RUNTIME_CTX just yet
                auto idx = llir::PPC64RegisterGPRIndex(reg);
                if (idx == SCRATCH || idx == RUNTIME_CTX)
                    continue;

                [[fallthrough]];
            }
            case llir::PPC64RegisterType::FPR:
            case llir::PPC64RegisterType::VSR:
            case llir::PPC64RegisterType::VR:
                loadstore_context_reg<T>(a, RUNTIME_CTX, reg, true, false);
                break;

            default:
                break;
        }
    }

    // Restore LR
    a.ld(SCRATCH, RUNTIME_CTX, offsetof(runtime_context_ppc64le, host_translated_context.lr));
    a.mtspr(SPR::LR, SCRATCH);

    // Invalidate icache if flush_icache flag is set
    a.lbz(SCRATCH, RUNTIME_CTX, offsetof(runtime_context_ppc64le, flush_icache));
    a.cmplwi(0, SCRATCH, 0);

    // Load entrypoint (NIP) into scratch and move to CTR
    a.ld(SCRATCH, RUNTIME_CTX, offsetof(runtime_context_ppc64le, host_translated_context.nip));
    a.mtspr(SPR::CTR, SCRATCH);

    // Skip icache invalidation if not requested
    a.bc(BO::FIELD_SET, 0*4 + assembler::CR_EQ, 0); RELOC_FIXUP_LABEL("skip_icache", AFTER);

    // Sequence from page 824 of ISA 3.0B
    // This works on the address in scratch which is still the entrypoint
    a.dcbst(0, SCRATCH);
    a.sync(0);
    a.icbi(0, SCRATCH);
    a.isync();

    // Unset flush icache_flag
    a.li(SCRATCH, 0);
    a.std(SCRATCH, RUNTIME_CTX, offsetof(runtime_context_ppc64le, flush_icache));

    // Restore CR
    RELOC_DECLARE_LABEL_AFTER("skip_icache");
    a.ld(SCRATCH, RUNTIME_CTX, offsetof(runtime_context_ppc64le, host_translated_context.cr));
    a.mtcr(SCRATCH);

    // Restore r3/rScratch and jump to code
    a.ld(SCRATCH, RUNTIME_CTX, offsetof(runtime_context_ppc64le, host_translated_context.gprs[SCRATCH]));
    a.ld(RUNTIME_CTX, RUNTIME_CTX, offsetof(runtime_context_ppc64le, host_translated_context.gprs[RUNTIME_CTX]));
    a.bctr();
}
PPC64LE_INSTANTIATE_CODEGEN_MEMBER(void, fixed_helper$enter_translated_code$emit, gen_context &)

/**
 * Emit the fixed helper for exiting translated code into native ELFv2 code.
 *
 * Routine description:
 * This is the opposite of enter_translated_code - it is used by translated code to re-enter
 * native ELFv2 code.
 *
 * Calling convention:
 *   (runtime_context_ppc64le *) [GPR_FIXED_RUNTIME_CTX] - Runtime context struct to exit.
 *
 * Note: Only non-volatle registers designated by ELFv2 will be restored. Any
 * registers marked as volatile by ELFv2 will not be restored.
 *
 * All registers marked as non-volatile by the ABIRetrec will be saved.
 */
template <typename T>
void codegen_ppc64le<T>::fixed_helper$leave_translated_code$emit(gen_context &ctx) {
    auto &a = *ctx.assembler;

    // Save all ABIRetrec non-special non-volatile registers
    for (auto reg : ABIRetrec<T>::non_volatile_regs) {
        switch (llir::PPC64RegisterGetType(reg)) {
            case llir::PPC64RegisterType::GPR:
            case llir::PPC64RegisterType::FPR:
            case llir::PPC64RegisterType::VSR:
            case llir::PPC64RegisterType::VR:
                loadstore_context_reg<T>(a, GPR_FIXED_RUNTIME_CTX, reg, false, false);
                break;

            default:
                break;
        }
    }

    // Save LR as NIP for re-entry later
    constexpr gpr_t SCRATCH = 3;
    a.mfspr(SCRATCH, SPR::LR);
    a.std(SCRATCH, GPR_FIXED_RUNTIME_CTX, offsetof(runtime_context_ppc64le, host_translated_context.nip));

    // Save CR
    a.mfcr(SCRATCH);
    a.std(SCRATCH, GPR_FIXED_RUNTIME_CTX, offsetof(runtime_context_ppc64le, host_translated_context.cr));

    // Restore all ELFv2 non-special non-volatile registers
    for (auto reg : ABIRetrec<T>::non_volatile_regs) {
        switch (llir::PPC64RegisterGetType(reg)) {
            case llir::PPC64RegisterType::GPR:
            {
                // Don't restore the scratch register or GPR_FIXED_RUNTIME_CTX
                auto idx = llir::PPC64RegisterGPRIndex(reg);
                if (idx == SCRATCH || idx == GPR_FIXED_RUNTIME_CTX)
                    continue;

                [[fallthrough]];
            }
            case llir::PPC64RegisterType::FPR:
            case llir::PPC64RegisterType::VSR:
            case llir::PPC64RegisterType::VR:
                loadstore_context_reg<T>(a, GPR_FIXED_RUNTIME_CTX, reg, true, true);
                break;

            default:
                break;
        }
    }

    // Restore LR, CR
    a.ld(SCRATCH, GPR_FIXED_RUNTIME_CTX, offsetof(runtime_context_ppc64le, host_native_context.lr));
    a.mtspr(SPR::LR, SCRATCH);
    a.ld(SCRATCH, GPR_FIXED_RUNTIME_CTX, offsetof(runtime_context_ppc64le, host_native_context.cr));
    a.mtcr(SCRATCH);

    // Restore GPR_FIXED_RUNTIME_CTX and SCRATCH
    a.ld(SCRATCH, GPR_FIXED_RUNTIME_CTX, offsetof(runtime_context_ppc64le, host_native_context.gprs[SCRATCH]));
    a.ld(GPR_FIXED_RUNTIME_CTX, GPR_FIXED_RUNTIME_CTX, offsetof(runtime_context_ppc64le, host_native_context.gprs[GPR_FIXED_RUNTIME_CTX]));

    // Return
    a.blr();
}
PPC64LE_INSTANTIATE_CODEGEN_MEMBER(void, fixed_helper$leave_translated_code$emit, gen_context &)

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
PPC64LE_INSTANTIATE_CODEGEN_MEMBER(void, fixed_helper$call$emit, gen_context &)

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
PPC64LE_INSTANTIATE_CODEGEN_MEMBER(void, fixed_helper$call_direct$emit, gen_context &, bool)

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
PPC64LE_INSTANTIATE_CODEGEN_MEMBER(void, fixed_helper$indirect_jmp$emit, gen_context &)

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
PPC64LE_INSTANTIATE_CODEGEN_MEMBER(void, fixed_helper$jmp_direct_rel$emit, gen_context &)

template <typename T>
void codegen_ppc64le<T>::fixed_helper$syscall$emit(gen_context &ctx) {
    macro$interrupt$trap(ctx, runtime_context_ppc64le::NativeTarget::SYSCALL, false);
}
PPC64LE_INSTANTIATE_CODEGEN_MEMBER(void, fixed_helper$syscall$emit, gen_context &)

template <typename T>
void codegen_ppc64le<T>::fixed_helper$trap_patch_call$emit(gen_context &ctx) {
    macro$interrupt$trap(ctx, runtime_context_ppc64le::NativeTarget::PATCH_CALL, false);
}
PPC64LE_INSTANTIATE_CODEGEN_MEMBER(void, fixed_helper$trap_patch_call$emit, gen_context &)

template <typename T>
void codegen_ppc64le<T>::fixed_helper$trap_patch_jump$emit(gen_context &ctx) {
    macro$interrupt$trap(ctx, runtime_context_ppc64le::NativeTarget::PATCH_JUMP, false);
}
PPC64LE_INSTANTIATE_CODEGEN_MEMBER(void, fixed_helper$trap_patch_jump$emit, gen_context &)

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
PPC64LE_INSTANTIATE_CODEGEN_MEMBER(void, fixed_helper$imul_overflow$emit, gen_context &)

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
PPC64LE_INSTANTIATE_CODEGEN_MEMBER(void, fixed_helper$shift_carry$emit, gen_context &)

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
PPC64LE_INSTANTIATE_CODEGEN_MEMBER(void, fixed_helper$shift_overflow$emit, gen_context &)

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
        auto func_reg = ctx.reg_allocator().get_fixed_reg(llir::X86_64Register::RAX);
        auto subfunc_reg = ctx.reg_allocator().get_fixed_reg(llir::X86_64Register::RCX);

        // Call x86_64::get_cpuid
        macro$load_imm(a, 12, (uintptr_t)&x86_64::get_cpuid, llir::Register::Mask::Full64, true);
        a.mtspr(SPR::CTR, 12);
        macro$call_native_function(ctx, func_reg.gpr(), subfunc_reg.gpr(), out_ptr_reg);
    }

    // Load EAX,EBX,ECX,EDX from result
    auto eax = ctx.reg_allocator().get_fixed_reg(llir::X86_64Register::RAX);
    auto ebx = ctx.reg_allocator().get_fixed_reg(llir::X86_64Register::RBX);
    auto ecx = ctx.reg_allocator().get_fixed_reg(llir::X86_64Register::RCX);
    auto edx = ctx.reg_allocator().get_fixed_reg(llir::X86_64Register::RDX);
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
PPC64LE_INSTANTIATE_CODEGEN_MEMBER(void, fixed_helper$cpuid$emit, gen_context &)

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
PPC64LE_INSTANTIATE_CODEGEN_MEMBER(void, fixed_helper$mul_overflow$emit, gen_context &)

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

            case llir::PPC64RegisterType::VSR:
                a.stxv(llir::PPC64RegisterVSRIndex(reg), GPR_SP, -16);
                a.addi(GPR_SP, GPR_SP, -16);
                break;

            case llir::PPC64RegisterType::VR:
                a.stxv(32 + llir::PPC64RegisterVSRIndex(reg), GPR_SP, -16);
                a.addi(GPR_SP, GPR_SP, -16);
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

            case llir::PPC64RegisterType::VSR:
                a.lxv(llir::PPC64RegisterVSRIndex(reg), GPR_SP, stack_offset);
                stack_offset += -16;
                break;

            case llir::PPC64RegisterType::VR:
                a.lxv(32 + llir::PPC64RegisterVRIndex(reg), GPR_SP, stack_offset);
                stack_offset += -16;
                break;

            default:
                TODO();
        }
    }
}
