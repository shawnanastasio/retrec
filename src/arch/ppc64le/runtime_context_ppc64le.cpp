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

#include <arch/ppc64le/runtime_context_ppc64le.h>
#include <arch/ppc64le/codegen/abi.h>
#include <platform/syscall_emulator.h>
#include <codegen.h>

#include <cstdlib>
#include <cstring>

using namespace retrec;
using namespace ppc64le;
using NativeTarget = runtime_context_ppc64le::NativeTarget;

//
// runtime_context_ppc64le
//

static status_code native_callback$syscall(runtime_context_ppc64le *ctx);

template <typename TargetTraits, typename RetT>
RetT *runtime_context_get_reg(runtime_context_ppc64le *ctx, typename TargetTraits::RegisterT reg) {
    // For statically allocated registers, return the corresponding ppc64 register from the translated context
    for (auto &pair : TargetABIMapping<TargetTraits>::fixed_regs) {
        if (reg == pair.target && (llir::PPC64RegisterGetType(pair.host) == llir::PPC64RegisterType::GPR)) {
            return &ctx->host_translated_context.gprs[llir::PPC64RegisterGPRIndex(pair.host)];
        }
    }

    // Otherwise, return the register from the appropriate target context
    switch (ctx->arch) {
        case Architecture::X86_64:
            return ctx->x86_64_ucontext.get_reg<RetT>(reg);
        default:
            TODO();
    }
}

status_code runtime_context_ppc64le::init(Architecture target_arch, void *entry, void *stack, virtual_address_mapper *vam_,
                                          syscall_emulator *syscall_emu_) {
    arch = target_arch;
    leave_translated_code_ptr = arch_leave_translated_code;
    syscall_emu = syscall_emu_;

    switch (target_arch) {
        case Architecture::X86_64:
            new(&x86_64_ucontext) cpu_context_x86_64();
            *runtime_context_get_reg<TargetTraitsX86_64, int64_t>(this, llir::X86_64Register::RSP) = (uint64_t)stack;
            break;

        default:
            TODO();
    }

    // Setup virtual address mapper
    vam = vam_;
    vam_lookup_and_update_call_cache = &virtual_address_mapper::lookup_and_update_call_cache;
    vam_lookup_check_call_cache = &virtual_address_mapper::lookup_check_call_cache;

    // HAddrT lookup_check_call_cache(VAddrT target);
    // Setup special registers
    host_translated_context.gprs[11] = (uint64_t)this; // R11 - runtime_context pointer
    host_translated_context.nip = (uint64_t)entry;
    asm volatile("mr %0, 13\n" : "=r"(host_translated_context.gprs[13]));

    return status_code::SUCCESS;
}

status_code runtime_context_ppc64le::execute() {
    for (;;) {
        pr_info("Entering translated code at 0x%lx\n", host_translated_context.nip);
        arch_enter_translated_code(nullptr, this);
        pr_info("Left translated code\n");

        // If the translated code wanted to call a native function, do so and resume
        switch (native_function_call_target) {
            case NativeTarget::SYSCALL:
            {
                status_code res = native_callback$syscall(this);
                if (res != status_code::SUCCESS)
                    return res;

                break;
            }

            case NativeTarget::CALL:
            case NativeTarget::JUMP:
            case NativeTarget::PATCH_CALL:
            case NativeTarget::PATCH_JUMP:
                // Translated code attempted to branch to untranslated code
                return status_code::UNTRANSLATED;

            case NativeTarget::INVALID:
                pr_debug("BUG: Translated code trapped to runtime without specifying a valid NativeTarget\n");
                ASSERT_NOT_REACHED();
        }
        native_function_call_target = runtime_context_ppc64le::NativeTarget::INVALID;

        if (should_exit) {
            pr_info("Emulation halted after native function call.\n");
            pr_info("Exit code: %d\n", exit_code);
            break;
        }
    }

    return status_code::HALT;
}

//
// Native callbacks
//

static status_code native_callback$syscall(runtime_context_ppc64le *ctx) {
    switch (ctx->arch) {
        case Architecture::X86_64:
        {
            int64_t syscall_number = *runtime_context_get_reg<TargetTraitsX86_64, int64_t>(ctx, llir::X86_64Register::RAX);
            SyscallParameters params {
                *runtime_context_get_reg<TargetTraitsX86_64, int64_t>(ctx, llir::X86_64Register::RDI),
                *runtime_context_get_reg<TargetTraitsX86_64, int64_t>(ctx, llir::X86_64Register::RSI),
                *runtime_context_get_reg<TargetTraitsX86_64, int64_t>(ctx, llir::X86_64Register::RDX),
                *runtime_context_get_reg<TargetTraitsX86_64, int64_t>(ctx, llir::X86_64Register::R10),
                *runtime_context_get_reg<TargetTraitsX86_64, int64_t>(ctx, llir::X86_64Register::R8),
                *runtime_context_get_reg<TargetTraitsX86_64, int64_t>(ctx, llir::X86_64Register::R9)
            };
            auto syscall_ret_maybe = ctx->syscall_emu->emulate_syscall(syscall_number, params);
            if (auto *res = std::get_if<status_code>(&syscall_ret_maybe))
                return *res;
            auto &syscall_ret = *std::get_if<SyscallRet>(&syscall_ret_maybe);

            // Fill response into context
            *runtime_context_get_reg<TargetTraitsX86_64, int64_t>(ctx, llir::X86_64Register::RAX) = syscall_ret.ret;
            if (syscall_ret.should_halt) {
                ctx->should_exit = true;
                ctx->exit_code = (int)syscall_ret.ret;
            }

            break;
        }

        default:
            TODO();
    }

    return status_code::SUCCESS;
}
