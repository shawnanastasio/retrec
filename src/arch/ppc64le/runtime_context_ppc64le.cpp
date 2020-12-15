#include <arch/ppc64le/runtime_context_ppc64le.h>
#include <arch/ppc64le/codegen/abi.h>
#include <platform/syscall_emulation.h>
#include <codegen.h>

#include <cstdlib>
#include <cstring>

using namespace retrec;
using namespace ppc64le;
using NativeTarget = runtime_context_ppc64le::NativeTarget;

//
// runtime_context_ppc64le
//

static void native_callback$syscall(runtime_context_ppc64le *ctx);
static void native_callback$call(runtime_context_ppc64le *ctx);

template <typename TargetTraits>
int64_t *runtime_context_get_reg(runtime_context_ppc64le *ctx, typename TargetTraits::RegisterT reg) {
    // For statically allocated registers, return the corresponding ppc64 register from the translated context
    for (auto &pair : TargetABIMapping<TargetTraits>::fixed_regs) {
        if (reg == pair.target && (llir::PPC64RegisterGetType(pair.host) == llir::PPC64RegisterType::GPR)) {
            return &ctx->host_translated_context.gprs[llir::PPC64RegisterGPRIndex(pair.host)];
        }
    }

    // Otherwise, return the register from the appropriate target context
    switch (ctx->arch) {
        case Architecture::X86_64:
            return ctx->x86_64_ucontext.get_reg(reg);
        default:
            TODO();
    }
}

status_code ppc64le::runtime_context_init(runtime_context_ppc64le *ctx, Architecture target_arch,
                                          translated_code_region *code, void *stack) {
    memset(ctx, 0, sizeof(runtime_context_ppc64le));
    ctx->arch = target_arch;
    ctx->leave_translated_code_ptr = arch_leave_translated_code;

    switch (target_arch) {
        case Architecture::X86_64:
            *runtime_context_get_reg<TargetTraitsX86_64>(ctx, llir::X86_64Register::RSP) = (uint64_t)stack;
            break;

        default:
            TODO();
    }

    // Setup virtual address mapper
    ctx->vm_lut = &g_virtual_address_mapper;
    ctx->vm_lut_lookup_and_update_call_cache = &virtual_address_mapper::lookup_and_update_call_cache;
    ctx->vm_lut_lookup_check_call_cache = &virtual_address_mapper::lookup_check_call_cache;

    // HAddrT lookup_check_call_cache(VAddrT target);
    // Setup special registers
    ctx->host_translated_context.gprs[11] = (uint64_t)ctx; // R11 - runtime_context pointer
    ctx->host_translated_context.nip = (uint64_t)code->code();
    __asm__ volatile("mr %0, 13\n" : "=r"(ctx->host_translated_context.gprs[13]));

    return status_code::SUCCESS;
}

status_code ppc64le::runtime_context_execute(runtime_context_ppc64le *ctx) {
    for (;;) {
        arch_enter_translated_code(nullptr, ctx);

        if (ctx->native_function_call_target != runtime_context_ppc64le::NativeTarget::INVALID) {
            // If the translated code wanted to call a native function, do so and resume
            switch (ctx->native_function_call_target) {
                case NativeTarget::SYSCALL:
                    native_callback$syscall(ctx);
                    break;

                case NativeTarget::CALL:
                    native_callback$call(ctx);
                    break;

                case NativeTarget::INVALID:
                    ASSERT_NOT_REACHED();
            }
            ctx->native_function_call_target = runtime_context_ppc64le::NativeTarget::INVALID;

            if (ctx->should_exit) {
                pr_info("Emulation halted after native function call.\n");
                pr_info("Exit code: %d\n", ctx->exit_code);
                break;
            }
        } else {
            // Left translated code without requesting a function call - translated code is done executing
            break;
        }
    }

    return status_code::SUCCESS;
}

//
// Native callbacks
//

static void native_callback$syscall(runtime_context_ppc64le *ctx) {
    switch (ctx->arch) {
        case Architecture::X86_64:
        {
            auto syscall_ret = get_syscall_emulator().emulate_syscall(
                *runtime_context_get_reg<TargetTraitsX86_64>(ctx, llir::X86_64Register::RAX),
                *runtime_context_get_reg<TargetTraitsX86_64>(ctx, llir::X86_64Register::RDI),
                *runtime_context_get_reg<TargetTraitsX86_64>(ctx, llir::X86_64Register::RSI),
                *runtime_context_get_reg<TargetTraitsX86_64>(ctx, llir::X86_64Register::RDX),
                *runtime_context_get_reg<TargetTraitsX86_64>(ctx, llir::X86_64Register::R10),
                *runtime_context_get_reg<TargetTraitsX86_64>(ctx, llir::X86_64Register::R8),
                *runtime_context_get_reg<TargetTraitsX86_64>(ctx, llir::X86_64Register::R9)
            );

            // Fill response into context
            *runtime_context_get_reg<TargetTraitsX86_64>(ctx, llir::X86_64Register::RAX) = syscall_ret.ret;
            if (syscall_ret.should_exit) {
                ctx->should_exit = true;
                ctx->exit_code = (int)syscall_ret.ret;
            }

            break;
        }

        default:
            TODO();
    }
}

static void native_callback$call([[maybe_unused]] runtime_context_ppc64le *ctx) {
    TODO();
}
