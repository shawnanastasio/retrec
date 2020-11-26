#pragma once

#include <util/util.h>
#include <platform/generic_syscalls.h>

#include <cstdint>

namespace retrec {

class syscall_emulator {
public:
    syscall_emulator(Architecture target) : target_arch(target) {}

    struct SyscallRet {
        int64_t ret;
        bool should_exit;
    };

    SyscallRet emulate_syscall(int64_t number, int64_t arg1, int64_t arg2, int64_t arg3,
                               int64_t arg4, int64_t arg5, int64_t arg6);
private:
    Architecture target_arch;

    GenericSyscall get_generic_syscall_number(int64_t number);
    SyscallRet sys$exit(int64_t arg1);
};

template <typename T>
void init_syscall_emulator(Architecture target) {
    extern syscall_emulator *g_syscall_emulator;
    assert(!g_syscall_emulator);
    g_syscall_emulator = new T(target);
}

static inline syscall_emulator &get_syscall_emulator() {
    extern syscall_emulator *g_syscall_emulator;
    assert(g_syscall_emulator);
    return *g_syscall_emulator;
}

}