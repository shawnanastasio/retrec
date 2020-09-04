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

    bool should_exit;
    int exit_code;
};

class translated_code_region;
namespace ppc64le {

status_code runtime_context_init(runtime_context_ppc64le *, Architecture, translated_code_region *);
status_code runtime_context_execute(runtime_context_ppc64le *);
static inline int64_t *runtime_context_get_reg(runtime_context_ppc64le *ctx, llir::X86_64Register reg) {
    /*
     * reserved_allocations[reserved_index(llir::X86_64Register::RDI)] = 3; gprs[3] = AllocationState::RESERVED;
     * reserved_allocations[reserved_index(llir::X86_64Register::RSI)] = 4; gprs[4] = AllocationState::RESERVED;
     * reserved_allocations[reserved_index(llir::X86_64Register::RDX)] = 5; gprs[5] = AllocationState::RESERVED;
     * reserved_allocations[reserved_index(llir::X86_64Register::RCX)] = 6; gprs[6] = AllocationState::RESERVED;
     * reserved_allocations[reserved_index(llir::X86_64Register::R8)]  = 7; gprs[7] = AllocationState::RESERVED;
     * reserved_allocations[reserved_index(llir::X86_64Register::R9)]  = 8; gprs[8] = AllocationState::RESERVED;
     * reserved_allocations[reserved_index(llir::X86_64Register::RAX)] = 9; gprs[9] = AllocationState::RESERVED;
     */
    // For statically allocated registers, return the corresponding ppc64 register from the translated context.
    // Otherwise, return the register from the x86_64_ucontext
    switch (reg) {
        case llir::X86_64Register::RDI:
            return ctx->host_translated_context.gprs + 3;
        case llir::X86_64Register::RSI:
            return ctx->host_translated_context.gprs + 4;
        case llir::X86_64Register::RDX:
            return ctx->host_translated_context.gprs + 5;
        case llir::X86_64Register::RCX:
            return ctx->host_translated_context.gprs + 6;
        case llir::X86_64Register::R8:
            return ctx->host_translated_context.gprs + 7;
        case llir::X86_64Register::R9:
            return ctx->host_translated_context.gprs + 8;
        case llir::X86_64Register::RAX:
            return ctx->host_translated_context.gprs + 9;

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