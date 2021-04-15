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

#pragma once

#include <util/util.h>
#include <arch/ppc64le/cpu_context_ppc64le.h>
#include <arch/x86_64/cpu_context_x86_64.h>
#include <virtual_address_mapper.h>

#include <unordered_map>

namespace retrec {

class syscall_emulator; // Forward

/**
 * Data accessed by translated code and retrec runtime
 */
struct runtime_context_ppc64le {
    //
    // State of translated CPU
    //
    cpu_context_ppc64le host_native_context;     // Host CPU context when in native code
    cpu_context_ppc64le host_translated_context; // Host CPU context when in translated code
    bool flush_icache { false }; // Whether to invalidate icache before jumping to translated code

    //
    // Storage used for communication between translated and native code
    //
    void (*leave_translated_code_ptr)(void) { nullptr };     // Function pointer to arch_leave_translated_code thunk

    // Pointers to virtual_address_mapper for use with things like indirect call resolution
    virtual_address_mapper *vam { nullptr };
    uint64_t (virtual_address_mapper::* vam_lookup_and_update_call_cache)(uint64_t, uint64_t, uint64_t) { nullptr };
    uint64_t (virtual_address_mapper::* vam_lookup_check_call_cache)(uint64_t) { nullptr };

    // If the translated code wishes to call into native code, it will set the target here
    enum class NativeTarget : uint16_t /* fit in an instruction immediate field */ {
        INVALID,
        SYSCALL,     // Execute a syscall
        CALL,        // Emulate a CALL instruction
        JUMP,        // Emulate a JUMP instruction
        PATCH_CALL,  // Patch in a direct CALL
        PATCH_JUMP,  // Patch in a direct JUMP
    } native_function_call_target { NativeTarget::INVALID };

    // Target CPU emulated context
    Architecture arch;
    union {
        cpu_context_x86_64 x86_64_ucontext;
    };

    bool should_exit { false };
    int exit_code { 0 };

    // Pointer to syscall emulator, used by native code
    syscall_emulator *syscall_emu { nullptr };

    //
    // Initialization and accessor functions
    //
    runtime_context_ppc64le() {}

    status_code init(Architecture target_arch, void *entry, void *stack, virtual_address_mapper *vam_,
                     syscall_emulator *syscall_emu_);
    status_code execute();
};
static_assert(std::is_standard_layout<runtime_context_ppc64le>::value, "Runtime context must have standard layout, since we access it manually from emitted ASM.");
static_assert(sizeof(runtime_context_ppc64le) <= 32768, "Runtime context must be accessible with signed 16-bit displacements!");

class translated_code_region;

#if HOST_ARCH_PPC64LE

// If the host architecture is ppc64le, set global runtime context definitions
struct runtime_context : public runtime_context_ppc64le {};

#endif

}
