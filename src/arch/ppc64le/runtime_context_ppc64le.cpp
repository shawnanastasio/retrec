#include <arch/ppc64le/runtime_context_ppc64le.h>
#include <codegen.h>
#include <platform/syscall_emulation.h>

#include <cstring>

using namespace retrec;

status_code ppc64le::runtime_context_init(runtime_context_ppc64le *ctx, Architecture target_arch, translated_code_region *code) {
    memset(ctx, 0, sizeof(runtime_context_ppc64le));
    ctx->arch = target_arch;

    // Setup special registers
    ctx->host_translated_context.gprs[11] = (uint64_t)ctx; // R11 - runtime_context pointer
    ctx->host_translated_context.nip = (uint64_t)code->code();

    return status_code::SUCCESS;
}


status_code ppc64le::runtime_context_execute(runtime_context_ppc64le *ctx) {
    for (;;) {
        arch_enter_translated_code(nullptr, ctx);

        if (ctx->native_function_call_target) {
            // If the translated code wanted to call a native function, do so and resume
            ctx->native_function_call_target(ctx);
            ctx->native_function_call_target = nullptr;

            if (ctx->should_exit) {
                log(LOGL_INFO, "Emulation halted after native function call.\n");
                log(LOGL_INFO, "Exit code: %d\n", ctx->exit_code);
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

