#include <arch/ppc64le/runtime_context_ppc64le.h>
#include <platform/syscall_emulation.h>
#include <codegen.h>

#include <cstring>

using namespace retrec;

status_code ppc64le::runtime_context_init(runtime_context_ppc64le *ctx,
                                          Architecture target_arch,
                                          translated_code_region *code, void *stack) {
    memset(ctx, 0, sizeof(runtime_context_ppc64le));
    ctx->arch = target_arch;
    ctx->leave_translated_code_ptr = arch_leave_translated_code;
    *runtime_context_get_reg(ctx, llir::X86_64Register::RSP) = (uint64_t)stack;

    // Setup special registers
    ctx->host_translated_context.gprs[11] = (uint64_t)ctx; // R11 - runtime_context pointer
    ctx->host_translated_context.nip = (uint64_t)code->code();

    return status_code::SUCCESS;
}


status_code ppc64le::runtime_context_execute(runtime_context_ppc64le *ctx) {
    for (;;) {
        arch_enter_translated_code(nullptr, ctx);

        if (ctx->native_function_call_target != runtime_context_ppc64le::NativeTarget::INVALID) {
            // If the translated code wanted to call a native function, do so and resume
            switch (ctx->native_function_call_target) {
                case runtime_context_ppc64le::NativeTarget::SYSCALL: syscall_native_callback(ctx); break;
                default: TODO();
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

void ppc64le::syscall_native_callback(runtime_context_ppc64le *ctx) {
    switch (ctx->arch) {
        case Architecture::X86_64:
        {
            auto syscall_ret = get_syscall_emulator().emulate_syscall(
                *runtime_context_get_reg(ctx, llir::X86_64Register::RAX),
                *runtime_context_get_reg(ctx, llir::X86_64Register::RDI),
                *runtime_context_get_reg(ctx, llir::X86_64Register::RSI),
                *runtime_context_get_reg(ctx, llir::X86_64Register::RDX),
                *runtime_context_get_reg(ctx, llir::X86_64Register::R10),
                *runtime_context_get_reg(ctx, llir::X86_64Register::R8),
                *runtime_context_get_reg(ctx, llir::X86_64Register::R9)
            );

            // Fill response into context
            *runtime_context_get_reg(ctx, llir::X86_64Register::RAX) = syscall_ret.ret;
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

