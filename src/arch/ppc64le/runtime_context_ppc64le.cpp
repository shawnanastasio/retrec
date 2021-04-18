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
#include <type_traits>

using namespace retrec;
using namespace ppc64le;
using NativeTarget = runtime_context_ppc64le::NativeTarget;

void (*arch_enter_translated_code_ptr)(void *runtime_context) = nullptr;
void (*arch_leave_translated_code_ptr)() = nullptr;

void arch_enter_translated_code(void *runtime_context) {
    arch_enter_translated_code_ptr(runtime_context);
}

//
// runtime_context_ppc64le
//

static status_code native_callback$syscall(runtime_context_ppc64le *ctx);

template <typename TargetTraits, typename RetT>
RetT *runtime_context_get_reg(runtime_context_ppc64le *ctx, typename TargetTraits::RegisterT reg) {
    // For statically allocated registers, return the corresponding ppc64 register from the translated context
    for (auto &pair : TargetABIMapping<TargetTraits>::fixed_regs) {
        if (reg != pair.target)
            continue;

        if (llir::PPC64RegisterGetType(pair.host) == llir::PPC64RegisterType::GPR) {
            if constexpr (types_are_same_v<RetT, decltype(ctx->host_translated_context.gprs[0])>)
                return &ctx->host_translated_context.gprs[llir::PPC64RegisterGPRIndex(pair.host)];
        } else if (llir::PPC64RegisterGetType(pair.host) == llir::PPC64RegisterType::VSR) {
            if constexpr (types_are_same_v<RetT, decltype(ctx->host_translated_context.vsr[0])>)
                return &ctx->host_translated_context.vsr[llir::PPC64RegisterVSRIndex(pair.host)];
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
    leave_translated_code_ptr = arch_leave_translated_code_ptr;
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
        pr_info("Entering translated code at 0x%lx, arch_enter_translated_code=%p\n", host_translated_context.nip,
                arch_enter_translated_code);
        arch_enter_translated_code(this);
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
            if constexpr (RETREC_DEBUG_BUILD)
                dump_emulated_machine_state();
            break;
        }
    }

    return status_code::HALT;
}

#ifdef RETREC_DEBUG_BUILD
template <size_t N, typename... Args>
void append_fmt_line(std::vector<std::string> &strs, size_t col_sizes[N], size_t idx, size_t col, const char *fmt, Args... args) {
    auto cumulative_col_size = [&] {
        size_t total = 0;
        for (size_t i = 0; i < col && i < N; i++)
            total += col_sizes[i];

        return total;
    };

    char buf[128];
    snprintf(buf, sizeof(buf), fmt, args...);
    if (col == 0) {
        strs.insert(strs.begin() + idx, buf);
    } else {
        assert(idx < strs.size());
        auto &cur = strs[idx];
        size_t cumulative_size = cumulative_col_size();
        for (size_t i = cur.size(); i < cumulative_size; i++)
            cur += " ";
        cur += buf;
    }
}

void runtime_context_ppc64le::dump_emulated_machine_state() {
    std::vector<std::string> s;
    size_t col_sizes[2] = {25, 43};

#define fmt(...) \
    append_fmt_line<ARRAY_SIZE(col_sizes)>(s, col_sizes, __VA_ARGS__)

    fmt(0,  0, "rax=0x%016lx", *runtime_context_get_reg<TargetTraitsX86_64, int64_t>(this, llir::X86_64Register::RAX));
    fmt(1,  0, "rbx=0x%016lx", *runtime_context_get_reg<TargetTraitsX86_64, int64_t>(this, llir::X86_64Register::RBX));
    fmt(2,  0, "rcx=0x%016lx", *runtime_context_get_reg<TargetTraitsX86_64, int64_t>(this, llir::X86_64Register::RCX));
    fmt(3,  0, "rdx=0x%016lx", *runtime_context_get_reg<TargetTraitsX86_64, int64_t>(this, llir::X86_64Register::RDX));
    fmt(4,  0, "rsp=0x%016lx", *runtime_context_get_reg<TargetTraitsX86_64, int64_t>(this, llir::X86_64Register::RSP));
    fmt(5,  0, "rbp=0x%016lx", *runtime_context_get_reg<TargetTraitsX86_64, int64_t>(this, llir::X86_64Register::RBP));
    fmt(6,  0, "rsi=0x%016lx", *runtime_context_get_reg<TargetTraitsX86_64, int64_t>(this, llir::X86_64Register::RSI));
    fmt(7,  0, "rdi=0x%016lx", *runtime_context_get_reg<TargetTraitsX86_64, int64_t>(this, llir::X86_64Register::RDI));
    fmt(8,  0, " r8=0x%016lx", *runtime_context_get_reg<TargetTraitsX86_64, int64_t>(this, llir::X86_64Register::R8));
    fmt(9,  0, " r9=0x%016lx", *runtime_context_get_reg<TargetTraitsX86_64, int64_t>(this, llir::X86_64Register::R9));
    fmt(10, 0, "r10=0x%016lx", *runtime_context_get_reg<TargetTraitsX86_64, int64_t>(this, llir::X86_64Register::R10));
    fmt(11, 0, "r11=0x%016lx", *runtime_context_get_reg<TargetTraitsX86_64, int64_t>(this, llir::X86_64Register::R11));
    fmt(12, 0, "r12=0x%016lx", *runtime_context_get_reg<TargetTraitsX86_64, int64_t>(this, llir::X86_64Register::R12));
    fmt(13, 0, "r13=0x%016lx", *runtime_context_get_reg<TargetTraitsX86_64, int64_t>(this, llir::X86_64Register::R13));
    fmt(14, 0, "r14=0x%016lx", *runtime_context_get_reg<TargetTraitsX86_64, int64_t>(this, llir::X86_64Register::R14));
    fmt(15, 0, "r15=0x%016lx", *runtime_context_get_reg<TargetTraitsX86_64, int64_t>(this, llir::X86_64Register::R15));

    auto fmt_xmm = [&](size_t line, size_t col, llir::X86_64Register reg) {
        auto& val = *runtime_context_get_reg<TargetTraitsX86_64, reg128>(this, reg);
        fmt(line,  col, "%sxmm%d=0x%016lx%016lx", ((int)reg < (int)llir::X86_64Register::XMM10) ? " " : "",
                (int)reg - (int)llir::X86_64Register::XMM0, val.le.hi, val.le.lo);
    };
    fmt_xmm(0, 1,  llir::X86_64Register::XMM0);
    fmt_xmm(1, 1,  llir::X86_64Register::XMM1);
    fmt_xmm(2, 1,  llir::X86_64Register::XMM2);
    fmt_xmm(3, 1,  llir::X86_64Register::XMM3);
    fmt_xmm(4, 1,  llir::X86_64Register::XMM4);
    fmt_xmm(5, 1,  llir::X86_64Register::XMM5);
    fmt_xmm(6, 1,  llir::X86_64Register::XMM6);
    fmt_xmm(7, 1,  llir::X86_64Register::XMM7);
    fmt_xmm(8, 1,  llir::X86_64Register::XMM8);
    fmt_xmm(9, 1,  llir::X86_64Register::XMM9);
    fmt_xmm(10, 1, llir::X86_64Register::XMM10);
    fmt_xmm(11, 1, llir::X86_64Register::XMM11);
    fmt_xmm(12, 1, llir::X86_64Register::XMM12);
    fmt_xmm(13, 1, llir::X86_64Register::XMM13);
    fmt_xmm(14, 1, llir::X86_64Register::XMM14);
    fmt_xmm(15, 1, llir::X86_64Register::XMM15);

    auto fmt_fr = [&](size_t line, size_t col, llir::X86_64Register reg) {
        auto &val = *runtime_context_get_reg<TargetTraitsX86_64, cpu_context_x86_64::x87_reg>(this, reg);
        fmt(line, col, "fr%d=0x%04x%016lx", (int)reg - (int)llir::X86_64Register::FR0, val.hi, val.lo);
    };
    fmt_fr(0, 2,  llir::X86_64Register::FR0);
    fmt_fr(1, 2,  llir::X86_64Register::FR1);
    fmt_fr(2, 2,  llir::X86_64Register::FR2);
    fmt_fr(3, 2,  llir::X86_64Register::FR3);
    fmt_fr(4, 2,  llir::X86_64Register::FR4);
    fmt_fr(5, 2,  llir::X86_64Register::FR5);
    fmt_fr(6, 2,  llir::X86_64Register::FR6);
    fmt_fr(7, 2,  llir::X86_64Register::FR7);

#undef fmt

    pr_debug("------ Emulated Machine State Dump ------\n");
    for (auto &str : s)
        pr_debug("%s\n", str.c_str());
    pr_debug("-----------------------------------------\n");
}
#endif

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
