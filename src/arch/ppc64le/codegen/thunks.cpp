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

/**
 * This file contains the implementation of thunks for entering/leaving
 * translated code on ppc64le hosts. As such, its compilation is guarded by
 * HOST_ARCH_PPC64LE.
 */

#include <arch/arch.h>

#if HOST_ARCH_PPC64LE

#include <arch/ppc64le/runtime_context_ppc64le.h>

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define RC_HOST_TRANSLATED_CONTEXT_OFFSET 744
static_assert(offsetof(retrec::runtime_context_ppc64le, host_translated_context) ==
              RC_HOST_TRANSLATED_CONTEXT_OFFSET,
              "Invalid retrec::runtime_context_ppc64le::host_translated_context offset"
              " Did you change the struct?");

#define RC_FLUSH_ICACHE_OFFSET 1488
static_assert(offsetof(retrec::runtime_context_ppc64le, flush_icache) == RC_FLUSH_ICACHE_OFFSET,
              "Invalid retrec::runtime_context_ppc64le::flush_icache offset"
              " Did you change the struct?");

static_assert(offsetof(retrec::runtime_context_ppc64le, host_native_context) == 0,
              "host_native_context must be the first member in runtime_context_ppc64le");

#define CC_GPRS_OFFSET 0
#define CC_LR_OFFSET (CC_GPRS_OFFSET + (32 * 8))
#define CC_CR_OFFSET (CC_LR_OFFSET + 8)
#define CC_NIP_OFFSET (CC_CR_OFFSET + 8)
#define CC_FPRS_OFFSET (CC_NIP_OFFSET + 8)
#define CC_VMX_OFFSET (CC_FPRS_OFFSET + (32 * 8) + 8 /* pad */)
#define CC_VRSAVE_OFFSET (CC_VMX_OFFSET + (12 * 2 * 8))
static_assert(offsetof(retrec::cpu_context_ppc64le, gprs) == CC_GPRS_OFFSET);
static_assert(offsetof(retrec::cpu_context_ppc64le, lr) == CC_LR_OFFSET);
static_assert(offsetof(retrec::cpu_context_ppc64le, cr) == CC_CR_OFFSET);
static_assert(offsetof(retrec::cpu_context_ppc64le, nip) == CC_NIP_OFFSET);
static_assert(offsetof(retrec::cpu_context_ppc64le, fprs) == CC_FPRS_OFFSET);
static_assert(offsetof(retrec::cpu_context_ppc64le, vmx) == CC_VMX_OFFSET);
static_assert(offsetof(retrec::cpu_context_ppc64le, vrsave) == CC_VRSAVE_OFFSET);

#define REG_ARR_OFF(base, idx) STR(base) "+" STR(idx) "*8"

__asm__(
    ".text\n"
    ".align 4\n"

    ////////////////////////////////
    // arch_enter_translated_code //
    ////////////////////////////////
    ".type arch_enter_translated_code @function\n"
    ".global arch_enter_translated_code\n"
    "arch_enter_translated_code:\n"
    ".cfi_startproc\n"

    //
    // Save all non-volatile registers in host_native_context (r4)
    //

    // Save GPRs
    "std 1,"  REG_ARR_OFF(CC_GPRS_OFFSET, 1) "(4)\n"
    "std 2,"  REG_ARR_OFF(CC_GPRS_OFFSET, 2) "(4)\n"
    "std 12," REG_ARR_OFF(CC_GPRS_OFFSET, 12) "(4)\n"
    "std 13," REG_ARR_OFF(CC_GPRS_OFFSET, 13) "(4)\n"
    "std 14," REG_ARR_OFF(CC_GPRS_OFFSET, 14) "(4)\n"
    "std 15," REG_ARR_OFF(CC_GPRS_OFFSET, 15) "(4)\n"
    "std 16," REG_ARR_OFF(CC_GPRS_OFFSET, 16) "(4)\n"
    "std 17," REG_ARR_OFF(CC_GPRS_OFFSET, 17) "(4)\n"
    "std 18," REG_ARR_OFF(CC_GPRS_OFFSET, 18) "(4)\n"
    "std 19," REG_ARR_OFF(CC_GPRS_OFFSET, 19) "(4)\n"
    "std 20," REG_ARR_OFF(CC_GPRS_OFFSET, 20) "(4)\n"
    "std 21," REG_ARR_OFF(CC_GPRS_OFFSET, 21) "(4)\n"
    "std 22," REG_ARR_OFF(CC_GPRS_OFFSET, 22) "(4)\n"
    "std 23," REG_ARR_OFF(CC_GPRS_OFFSET, 23) "(4)\n"
    "std 24," REG_ARR_OFF(CC_GPRS_OFFSET, 24) "(4)\n"
    "std 25," REG_ARR_OFF(CC_GPRS_OFFSET, 25) "(4)\n"
    "std 26," REG_ARR_OFF(CC_GPRS_OFFSET, 26) "(4)\n"
    "std 27," REG_ARR_OFF(CC_GPRS_OFFSET, 27) "(4)\n"
    "std 28," REG_ARR_OFF(CC_GPRS_OFFSET, 28) "(4)\n"
    "std 29," REG_ARR_OFF(CC_GPRS_OFFSET, 29) "(4)\n"
    "std 30," REG_ARR_OFF(CC_GPRS_OFFSET, 30) "(4)\n"
    "std 31," REG_ARR_OFF(CC_GPRS_OFFSET, 31) "(4)\n"

    // Save LR
    "mflr 5\n"
    "std 5," STR(CC_LR_OFFSET) "(4)\n"
    "std 5," STR(CC_NIP_OFFSET) "(4)\n"

    // Save CR
    "mfcr 5\n"
    "std 5," STR(CC_CR_OFFSET) "(4)\n"

    // Save FPRs
    "stfd 14," REG_ARR_OFF(CC_FPRS_OFFSET, 14) "(4)\n"
    "stfd 15," REG_ARR_OFF(CC_FPRS_OFFSET, 15) "(4)\n"
    "stfd 16," REG_ARR_OFF(CC_FPRS_OFFSET, 16) "(4)\n"
    "stfd 17," REG_ARR_OFF(CC_FPRS_OFFSET, 17) "(4)\n"
    "stfd 18," REG_ARR_OFF(CC_FPRS_OFFSET, 18) "(4)\n"
    "stfd 19," REG_ARR_OFF(CC_FPRS_OFFSET, 19) "(4)\n"
    "stfd 20," REG_ARR_OFF(CC_FPRS_OFFSET, 20) "(4)\n"
    "stfd 21," REG_ARR_OFF(CC_FPRS_OFFSET, 21) "(4)\n"
    "stfd 22," REG_ARR_OFF(CC_FPRS_OFFSET, 22) "(4)\n"
    "stfd 23," REG_ARR_OFF(CC_FPRS_OFFSET, 23) "(4)\n"
    "stfd 24," REG_ARR_OFF(CC_FPRS_OFFSET, 24) "(4)\n"
    "stfd 25," REG_ARR_OFF(CC_FPRS_OFFSET, 25) "(4)\n"
    "stfd 26," REG_ARR_OFF(CC_FPRS_OFFSET, 26) "(4)\n"
    "stfd 27," REG_ARR_OFF(CC_FPRS_OFFSET, 27) "(4)\n"
    "stfd 28," REG_ARR_OFF(CC_FPRS_OFFSET, 28) "(4)\n"
    "stfd 29," REG_ARR_OFF(CC_FPRS_OFFSET, 29) "(4)\n"
    "stfd 30," REG_ARR_OFF(CC_FPRS_OFFSET, 30) "(4)\n"
    "stfd 31," REG_ARR_OFF(CC_FPRS_OFFSET, 31) "(4)\n"

#ifdef __ALTIVEC__
    // Save VMX
    "li 5, " STR(CC_VMX_OFFSET) "\n"
    "stvxl 20, 4, 5\n"
    "addi 5, 5, 16\n"
    "stvxl 21, 4, 5\n"
    "addi 5, 5, 16\n"
    "stvxl 22, 4, 5\n"
    "addi 5, 5, 16\n"
    "stvxl 23, 4, 5\n"
    "addi 5, 5, 16\n"
    "stvxl 24, 4, 5\n"
    "addi 5, 5, 16\n"
    "stvxl 25, 4, 5\n"
    "addi 5, 5, 16\n"
    "stvxl 26, 4, 5\n"
    "addi 5, 5, 16\n"
    "stvxl 27, 4, 5\n"
    "addi 5, 5, 16\n"
    "stvxl 28, 4, 5\n"
    "addi 5, 5, 16\n"
    "stvxl 29, 4, 5\n"
    "addi 5, 5, 16\n"
    "stvxl 30, 4, 5\n"
    "addi 5, 5, 16\n"
    "stvxl 31, 4, 5\n"
    "addi 5, 5, 16\n"

    // Save VRSAVE
    "mfvrsave 5\n"
    "stw 5, " STR(CC_VRSAVE_OFFSET) "(4)\n"
#endif

    //
    // Restore all non-volatile AND volatile registers from host_translated_context
    //                                                 (r4+RC_HOST_TRANSLATED_CONTEXT_OFFSET)
    //
    //"addi 4, 4, " STR(RC_HOST_TRANSLATED_CONTEXT_OFFSET) "\n"

    // Restore GPRs
    "ld 1,"  REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 1) "(4)\n"
    "ld 2,"  REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 2) "(4)\n"
    // Skip GPR3/4 since we still need them. We'll restore them later down
    "ld 5,"  REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 5) "(4)\n"
    "ld 6,"  REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 6) "(4)\n"
    "ld 7,"  REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 7) "(4)\n"
    "ld 8,"  REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 8) "(4)\n"
    "ld 9,"  REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 9) "(4)\n"
    "ld 10," REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 10) "(4)\n"
    "ld 11," REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 11) "(4)\n"
    "ld 12," REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 12) "(4)\n"
    "ld 13," REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 13) "(4)\n"
    "ld 14," REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 14) "(4)\n"
    "ld 15," REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 15) "(4)\n"
    "ld 16," REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 16) "(4)\n"
    "ld 17," REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 17) "(4)\n"
    "ld 18," REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 18) "(4)\n"
    "ld 19," REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 19) "(4)\n"
    "ld 20," REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 20) "(4)\n"
    "ld 21," REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 21) "(4)\n"
    "ld 22," REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 22) "(4)\n"
    "ld 23," REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 23) "(4)\n"
    "ld 24," REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 24) "(4)\n"
    "ld 25," REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 25) "(4)\n"
    "ld 26," REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 26) "(4)\n"
    "ld 27," REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 27) "(4)\n"
    "ld 28," REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 28) "(4)\n"
    "ld 29," REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 29) "(4)\n"
    "ld 30," REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 30) "(4)\n"
    "ld 31," REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 31) "(4)\n"

    // Restore LR
    "ld 3," STR(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_LR_OFFSET) "(4)\n"
    "mtlr 3\n"

    // Invalidate instruction cache if requested
    "lbz 3, " STR(RC_FLUSH_ICACHE_OFFSET) "(4)\n"
    "cmplwi 3, 0\n"

    // Load NIP into CTR
    "ld 3, " STR(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_NIP_OFFSET) "(4)\n"
    "mtctr 3\n"

    "beq 1f\n" // skip invalidation

    // Invalid icache using sequence on page 842 of ISA 3.0 PDF
    "dcbst 0, 3\n"
    "sync\n"
    "icbi 0, 3\n"
    "isync\n"

    // Unset flush_icache flag
    "li 3, 0\n"
    "stb 3, " STR(RC_FLUSH_ICACHE_OFFSET) "(4)\n"

    // Restore CR
    "1: ld 3," STR(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_CR_OFFSET) "(4)\n"
    "mtcr 3\n"

    // Restore last GPRs and jump to code
    "ld 3," REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 3) "(4)\n"
    "ld 4," REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 4) "(4)\n"

    "translated_code_entrypoint: bctr\n"

    ".cfi_endproc\n"
    ".size arch_enter_translated_code, .-arch_enter_translated_code\n"
    ".global translated_code_entrypoint\n"


    ////////////////////////////////
    // arch_leave_translated_code //
    ////////////////////////////////
    ".type arch_leave_translated_code @function\n"
    ".global arch_leave_translated_code\n"
    "arch_leave_translated_code:\n"
    ".cfi_startproc\n"

    //
    // Save all registers that can be used by translated code into host_translated_context
    //
    "std 0, "  REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 0) "(11)\n"
    "std 1, "  REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 1) "(11)\n"
    "std 2, "  REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 2) "(11)\n"
    "std 3, "  REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 3) "(11)\n"
    "std 4, "  REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 4) "(11)\n"
    "std 5, "  REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 5) "(11)\n"
    "std 6, "  REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 6) "(11)\n"
    "std 7, "  REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 7) "(11)\n"
    "std 8, "  REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 8) "(11)\n"
    "std 9, "  REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 9) "(11)\n"
    "std 10, " REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 10) "(11)\n"
    "std 11, " REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 11) "(11)\n"
    "std 12, " REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 12) "(11)\n"
    "std 13, " REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 13) "(11)\n"
    "std 14, " REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 14) "(11)\n"
    "std 15, " REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 15) "(11)\n"
    "std 16, " REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 16) "(11)\n"
    "std 17, " REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 17) "(11)\n"
    "std 18, " REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 18) "(11)\n"
    "std 19, " REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 19) "(11)\n"
    "std 20, " REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 20) "(11)\n"
    "std 21, " REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 21) "(11)\n"
    "std 22, " REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 22) "(11)\n"
    "std 23, " REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 23) "(11)\n"
    "std 24, " REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 24) "(11)\n"
    "std 25, " REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 25) "(11)\n"
    "std 26, " REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 26) "(11)\n"
    "std 27, " REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 27) "(11)\n"
    "std 28, " REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 28) "(11)\n"
    "std 29, " REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 29) "(11)\n"
    "std 30, " REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 30) "(11)\n"
    "std 31, " REG_ARR_OFF(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_GPRS_OFFSET, 31) "(11)\n"

    // LR will need to have been saved by our caller

    // Save CR
    "mfcr 3\n"
    "std 3, " STR(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_CR_OFFSET) "(11)\n"

    // Save LR as NIP, so the execution will be resumed at caller's next instruction when we re-enter
    "mflr 3\n"
    "std 3, " STR(RC_HOST_TRANSLATED_CONTEXT_OFFSET + CC_NIP_OFFSET) "(11)\n"

    //
    // Restore native context
    //

    // Restore GPRs
    "ld 1, "  REG_ARR_OFF(CC_GPRS_OFFSET, 1) "(11)\n"
    "ld 2, "  REG_ARR_OFF(CC_GPRS_OFFSET, 2) "(11)\n"
    "ld 12, " REG_ARR_OFF(CC_GPRS_OFFSET, 12) "(11)\n"
    "ld 13, " REG_ARR_OFF(CC_GPRS_OFFSET, 13) "(11)\n"
    "ld 14, " REG_ARR_OFF(CC_GPRS_OFFSET, 14) "(11)\n"
    "ld 15, " REG_ARR_OFF(CC_GPRS_OFFSET, 15) "(11)\n"
    "ld 16, " REG_ARR_OFF(CC_GPRS_OFFSET, 16) "(11)\n"
    "ld 17, " REG_ARR_OFF(CC_GPRS_OFFSET, 17) "(11)\n"
    "ld 18, " REG_ARR_OFF(CC_GPRS_OFFSET, 18) "(11)\n"
    "ld 19, " REG_ARR_OFF(CC_GPRS_OFFSET, 19) "(11)\n"
    "ld 20, " REG_ARR_OFF(CC_GPRS_OFFSET, 20) "(11)\n"
    "ld 21, " REG_ARR_OFF(CC_GPRS_OFFSET, 21) "(11)\n"
    "ld 22, " REG_ARR_OFF(CC_GPRS_OFFSET, 22) "(11)\n"
    "ld 23, " REG_ARR_OFF(CC_GPRS_OFFSET, 23) "(11)\n"
    "ld 24, " REG_ARR_OFF(CC_GPRS_OFFSET, 24) "(11)\n"
    "ld 25, " REG_ARR_OFF(CC_GPRS_OFFSET, 25) "(11)\n"
    "ld 26, " REG_ARR_OFF(CC_GPRS_OFFSET, 26) "(11)\n"
    "ld 27, " REG_ARR_OFF(CC_GPRS_OFFSET, 27) "(11)\n"
    "ld 28, " REG_ARR_OFF(CC_GPRS_OFFSET, 28) "(11)\n"
    "ld 29, " REG_ARR_OFF(CC_GPRS_OFFSET, 29) "(11)\n"
    "ld 30, " REG_ARR_OFF(CC_GPRS_OFFSET, 30) "(11)\n"
    "ld 31, " REG_ARR_OFF(CC_GPRS_OFFSET, 31) "(11)\n"

    // Restore LR
    "ld 3, " STR(CC_LR_OFFSET) "(11)\n"
    "mtlr 3\n"

    // Restore CR
    "ld 3, " STR(CC_CR_OFFSET) "(11)\n"
    "mtcr 3\n"

    // Restore FPRs
    "lfd 14, " REG_ARR_OFF(CC_FPRS_OFFSET, 14) "(11)\n"
    "lfd 15, " REG_ARR_OFF(CC_FPRS_OFFSET, 15) "(11)\n"
    "lfd 16, " REG_ARR_OFF(CC_FPRS_OFFSET, 16) "(11)\n"
    "lfd 17, " REG_ARR_OFF(CC_FPRS_OFFSET, 17) "(11)\n"
    "lfd 18, " REG_ARR_OFF(CC_FPRS_OFFSET, 18) "(11)\n"
    "lfd 19, " REG_ARR_OFF(CC_FPRS_OFFSET, 19) "(11)\n"
    "lfd 20, " REG_ARR_OFF(CC_FPRS_OFFSET, 20) "(11)\n"
    "lfd 21, " REG_ARR_OFF(CC_FPRS_OFFSET, 21) "(11)\n"
    "lfd 22, " REG_ARR_OFF(CC_FPRS_OFFSET, 22) "(11)\n"
    "lfd 23, " REG_ARR_OFF(CC_FPRS_OFFSET, 23) "(11)\n"
    "lfd 24, " REG_ARR_OFF(CC_FPRS_OFFSET, 24) "(11)\n"
    "lfd 25, " REG_ARR_OFF(CC_FPRS_OFFSET, 25) "(11)\n"
    "lfd 26, " REG_ARR_OFF(CC_FPRS_OFFSET, 26) "(11)\n"
    "lfd 27, " REG_ARR_OFF(CC_FPRS_OFFSET, 27) "(11)\n"
    "lfd 28, " REG_ARR_OFF(CC_FPRS_OFFSET, 28) "(11)\n"
    "lfd 29, " REG_ARR_OFF(CC_FPRS_OFFSET, 29) "(11)\n"
    "lfd 30, " REG_ARR_OFF(CC_FPRS_OFFSET, 30) "(11)\n"
    "lfd 31, " REG_ARR_OFF(CC_FPRS_OFFSET, 31) "(11)\n"

#ifdef __ALTIVEC__
    // Restore VMX
    "li 3," STR(CC_VMX_OFFSET) "\n"
    "lvxl 20, 11, 3\n"
    "addi 3, 3, 16\n"
    "lvxl 21, 11, 3\n"
    "addi 3, 3, 16\n"
    "lvxl 22, 11, 3\n"
    "addi 3, 3, 16\n"
    "lvxl 23, 11, 3\n"
    "addi 3, 3, 16\n"
    "lvxl 24, 11, 3\n"
    "addi 3, 3, 16\n"
    "lvxl 25, 11, 3\n"
    "addi 3, 3, 16\n"
    "lvxl 26, 11, 3\n"
    "addi 3, 3, 16\n"
    "lvxl 27, 11, 3\n"
    "addi 3, 3, 16\n"
    "lvxl 28, 11, 3\n"
    "addi 3, 3, 16\n"
    "lvxl 29, 11, 3\n"
    "addi 3, 3, 16\n"
    "lvxl 30, 11, 3\n"
    "addi 3, 3, 16\n"
    "lvxl 31, 11, 3\n"
    "addi 3, 3, 16\n"

    // Restore VRSAVE
    "lwz 3, " STR(CC_VRSAVE_OFFSET) "(11)\n"
    "mtvrsave 3\n"
#endif

    // Load NIP and branch to target
    "ld 3, " STR(CC_NIP_OFFSET) "(11)\n"
    "mtctr 3\n"
    "bctr\n"

    ".cfi_endproc\n"
    ".size arch_leave_translated_code, .-arch_leave_translated_code\n"
);

#endif
