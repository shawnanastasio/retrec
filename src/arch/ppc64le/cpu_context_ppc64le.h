#pragma once

#include <llir.h>

#include <cstdint>
#include <cstddef>

namespace retrec {

struct cpu_context_ppc64le {
    int64_t gprs[32];
    int64_t lr;
    int64_t cr;
    int64_t nip;

    int64_t fprs[32];

    int64_t _pad0;
    int64_t vmx[12 * 2];
    int32_t vrsave;
};

static_assert(offsetof(cpu_context_ppc64le, vmx) % 16 == 0, "VMX registers not quadword aligned!\n");

}