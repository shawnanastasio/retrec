#pragma once

#include <util.h>
#include <arch/arch.h>
#include <arch/x86_64/cpu_context_x86_64.h>
#include <arch/ppc64le/cpu_context_ppc64le.h>

namespace retrec {

struct runtime_context_ppc64le {
    cpu_context_ppc64le host_native_context;     // Host CPU context when in native code
    cpu_context_ppc64le host_translated_context; // Host CPU context when in translated code

    //
    // Storage used for communication between translated and native code
    //

    // If the translated code wishes to call into native code, it will set the target here
    enum class NativeTarget : uint16_t /* fit in an instruction immediate field */ {
        INVALID,
        SYSCALL, // Execute a syscall
    } native_function_call_target;

    // Target CPU emulated context
    Architecture arch;
    union {
        cpu_context_x86_64 x86_64_ucontext;
    };

    // Last executed operation that may have modified native flags. Used for lazy evaluation of
    // flag types that don't natively map to the Power ISA.
    int64_t last_flag_operands[2];
    enum class LastFlagOp {
        SUB,
    } last_flag_operation;

    bool should_exit;
    int exit_code;
};
static_assert(std::is_pod<runtime_context_ppc64le>::value, "Runtime context must be POD, since we access it manually from emitted ASM.");
static_assert(sizeof(runtime_context_ppc64le) <= 65535, "Runtime context must be accessible with 16-bit displacements!");

class translated_code_region;
namespace ppc64le {

status_code runtime_context_init(runtime_context_ppc64le *, Architecture, translated_code_region *);
status_code runtime_context_execute(runtime_context_ppc64le *);
static inline int64_t *runtime_context_get_reg(runtime_context_ppc64le *ctx, llir::X86_64Register reg) {
    // For statically allocated registers, return the corresponding ppc64 register from the translated context.
    // Otherwise, return the register from the x86_64_ucontext
    switch (reg) {
        case llir::X86_64Register::RDI:
            return &ctx->host_translated_context.gprs[3];
        case llir::X86_64Register::RSI:
            return &ctx->host_translated_context.gprs[4];
        case llir::X86_64Register::RDX:
            return &ctx->host_translated_context.gprs[5];
        case llir::X86_64Register::RCX:
            return &ctx->host_translated_context.gprs[6];
        case llir::X86_64Register::R8:
            return &ctx->host_translated_context.gprs[7];
        case llir::X86_64Register::R9:
            return &ctx->host_translated_context.gprs[8];
        case llir::X86_64Register::RAX:
            return &ctx->host_translated_context.gprs[9];

        default:
            return ctx->x86_64_ucontext.get_reg(reg);
    }
}
void syscall_native_callback(runtime_context_ppc64le *);

};

#if HOST_ARCH_PPC64LE

// If the host architecture is ppc64le, set global runtime context definitions

using runtime_context = runtime_context_ppc64le;
using ppc64le::runtime_context_init;
using ppc64le::runtime_context_execute;

#endif

}