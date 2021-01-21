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

#include <arch/x86_64/target_environment.h>
#include <util/util.h>

#include <cstdint>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>

#include <libelf.h>

using namespace retrec;
using namespace retrec::x86_64;

/* CPUID[01h].ECX values */
[[maybe_unused]] constexpr uint32_t CPUID_FEATURE_ECX_SSE3       = (1 << 0);
[[maybe_unused]] constexpr uint32_t CPUID_FEATURE_ECX_PCLMULQDQ  = (1 << 1);
[[maybe_unused]] constexpr uint32_t CPUID_FEATURE_ECX_DTES64     = (1 << 2);
[[maybe_unused]] constexpr uint32_t CPUID_FEATURE_ECX_MONITOR    = (1 << 3);
[[maybe_unused]] constexpr uint32_t CPUID_FEATURE_ECX_DS_CPL     = (1 << 4);
[[maybe_unused]] constexpr uint32_t CPUID_FEATURE_ECX_VMX        = (1 << 5);
[[maybe_unused]] constexpr uint32_t CPUID_FEATURE_ECX_SMX        = (1 << 6);
[[maybe_unused]] constexpr uint32_t CPUID_FEATURE_ECX_EIST       = (1 << 7);
[[maybe_unused]] constexpr uint32_t CPUID_FEATURE_ECX_TM2        = (1 << 8);
[[maybe_unused]] constexpr uint32_t CPUID_FEATURE_ECX_SSSE3      = (1 << 9);
[[maybe_unused]] constexpr uint32_t CPUID_FEATURE_ECX_CNXT_ID    = (1 << 10);
[[maybe_unused]] constexpr uint32_t CPUID_FEATURE_ECX_SDBG       = (1 << 11);
[[maybe_unused]] constexpr uint32_t CPUID_FEATURE_ECX_FMA        = (1 << 12);
[[maybe_unused]] constexpr uint32_t CPUID_FEATURE_ECX_CMPXCHG16B = (1 << 13);
[[maybe_unused]] constexpr uint32_t CPUID_FEATURE_ECX_XTPRUC     = (1 << 14);
[[maybe_unused]] constexpr uint32_t CPUID_FEATURE_ECX_PDCM       = (1 << 15);
[[maybe_unused]] constexpr uint32_t CPUID_FEATURE_ECX_PCID       = (1 << 17);
[[maybe_unused]] constexpr uint32_t CPUID_FEATURE_ECX_DCA        = (1 << 18);
[[maybe_unused]] constexpr uint32_t CPUID_FEATURE_ECX_SSE41      = (1 << 19);
[[maybe_unused]] constexpr uint32_t CPUID_FEATURE_ECX_SSE42      = (1 << 20);
[[maybe_unused]] constexpr uint32_t CPUID_FEATURE_ECX_X2APIC     = (1 << 21);
[[maybe_unused]] constexpr uint32_t CPUID_FEATURE_ECX_MOVBE      = (1 << 22);
[[maybe_unused]] constexpr uint32_t CPUID_FEATURE_ECX_POPCNT     = (1 << 23);
[[maybe_unused]] constexpr uint32_t CPUID_FEATURE_ECX_TSCDEADLN  = (1 << 24);
[[maybe_unused]] constexpr uint32_t CPUID_FEATURE_ECX_AESNI      = (1 << 25);
[[maybe_unused]] constexpr uint32_t CPUID_FEATURE_ECX_XSAVE      = (1 << 26);
[[maybe_unused]] constexpr uint32_t CPUID_FEATURE_ECX_OSXSAVE    = (1 << 27);
[[maybe_unused]] constexpr uint32_t CPUID_FEATURE_ECX_AVX        = (1 << 28);
[[maybe_unused]] constexpr uint32_t CPUID_FEATURE_ECX_F16C       = (1 << 29);
[[maybe_unused]] constexpr uint32_t CPUID_FEATURE_ECX_RDRAND     = (1 << 30);

constexpr uint32_t RETREC_CPUID_FEATURES_ECX = 0;

/**
 * Build an ELF auxiliary vector on the target stack. Mimicks the vector that QEMU builds.
 */
static void build_elf_aux(uint64_t *&sp64, const elf_loader &loader,
                          const std::vector<uint8_t *> &argv_offsets) {
    auto push_entry = [&](uint64_t type, uint64_t val) {
        *(--sp64) = val;
        *(--sp64) = type;
    };

    // Push the string "x86_64\0\0" for AT_PLATFORM. Real Linux/QEMU doesn't seem
    // to store this string on the stack, but there's nothing that says you can't.
    *(--sp64) = 0x000034365f363878ul; // "x86_64\0\0" as a little endian u64
    char *platform_name_ptr = (char *)sp64;

    // Push 16 random bytes for AT_RANDOM. Same deal as AT_PLATFORM - real Linux doesn't
    // use the stack for this but we should be free to do so.
    //
    // Guaranteed 100% random number :)
    *(--sp64) = 0xDEADBEEFCAFEBABA;
    *(--sp64) = 0xFACEFEED2BADC0DE;
    char *random_ptr = (char *)sp64;

    // We're building in reverse, so AT_NULL goes first
    push_entry(AT_NULL, 0);

    // Push the rest of the entries in the order that QEMU does
    push_entry(AT_PLATFORM, (uint64_t)platform_name_ptr);
    push_entry(AT_EXECFN,   (uint64_t)argv_offsets[0]); // Reuse argv[0] for program name pointer
    push_entry(AT_SECURE,   0 /* lol */);
    push_entry(AT_RANDOM,   (uint64_t)random_ptr);
    push_entry(AT_CLKTCK,   100); // Same value QEMU returns - not sure if we really need to calculate this.
    push_entry(AT_HWCAP,    RETREC_CPUID_FEATURES_ECX); // The same as CPUID[01h].EDX
    push_entry(AT_EGID,     getegid());
    push_entry(AT_GID,      getgid());
    push_entry(AT_EUID,     geteuid());
    push_entry(AT_UID,      getuid());
    push_entry(AT_ENTRY,    loader.entrypoint());
    push_entry(AT_FLAGS,    0);
    push_entry(AT_BASE,     0);
    push_entry(AT_PAGESZ,   getpagesize());
    push_entry(AT_PHNUM,    loader.get_ehdr().e_phnum);
    push_entry(AT_PHENT,    loader.get_ehdr().e_phentsize);
    push_entry(AT_PHDR,     loader.get_base_address() + loader.get_ehdr().e_phoff);
}

void *x86_64::initialize_target_stack(void *stack, const std::vector<std::string> &argv,
                               const std::vector<std::string> &envp, const elf_loader &elf_loader) {
    // Initialize the stack with argc/argv/envp process arguments as expected by an
    // x86_64 linux userspace process. The stack will look like this after we're done:
    //
    // top -->+---------------------+
    //        |                     |
    //        |  /* STRING POOL */  | <--+
    //        |                     |    |
    //        + ------------------- +    |
    //        |         elf_aux[n]  |    |
    //        | /* elf     ...      |    |
    //        |    aux */  ...      |    |
    //        |         elf_aux[0]  |    |
    //        + ------------------- +    |
    //        |              NULL   |    |
    //        |            envp[n]  | ---+
    //        | /* envp */   ...    |    |
    //        |            envp[0]  | ---+
    //        + ------------------- +    |
    //        |              NULL   |    |
    //        |            argv[n]  | ---+
    //        | /* argv */   ...    |    |
    //        |            argv[0]  | ---+
    //        + --------------------+
    // sp --> |      /* argc */     |
    //        +---------------------+
    //
    uint8_t *sp = (uint8_t *)stack;

    auto push_string = [&](const auto &str) {
        *(--sp) = '\0';
        for (size_t i = str.size(); i-- > 0;)
            *(--sp) = str[i];
    };

    // Dump argv/envp strings on to the stack first
    std::vector<uint8_t *> argv_offsets;
    std::vector<uint8_t *> envp_offsets;
    for (const auto &str : argv) {
        // Push string and save start offset
        push_string(str);
        argv_offsets.push_back(sp);
    }
    for (const auto &str : envp) {
        // Push string and save start offset
        push_string(str);
        envp_offsets.push_back(sp);
    }

    // Align stack to 8 bytes
    sp = (uint8_t *)((uintptr_t)sp & ~0b111);
    uint64_t *sp64 = (uint64_t *)sp;

    // Build ELF auxiliary vector
    build_elf_aux(sp64, elf_loader, argv_offsets);

    // Push envp pointers in reverse
    *(--sp64) = 0;
    for (size_t i = envp_offsets.size(); i-- > 0;) {
        *(--sp64) = (uint64_t)envp_offsets[i];
    }

    // Push argv pointers in reverse
    *(--sp64) = 0;
    for (size_t i = argv_offsets.size(); i-- > 0;) {
        *(--sp64) = (uint64_t)argv_offsets[i];
    }

    // Push argc
    *(--sp64) = argv.size();

    return sp64;
}


void x86_64::get_cpuid(uint32_t func, uint32_t subfunc, CpuidResult *res) {
    // For now, we just return the values that `qemu-x86_64 -cpu Westmere` does.
    // In the future we'll want to support multiple virtual CPU models selectable
    // at run-time, and the CPUID should reflect that.
    memset(res, 0, sizeof(*res));

    switch (func) {
        case 0x00:
            // GenuineIntel :)
            res->eax = 0x0000000B;
            res->ebx = 0x756E6547;
            res->ecx = 0x6C65746E;
            res->edx = 0x69746E65;
            break;

        case 0x01:
            res->eax = 0x00800F11;
            res->ebx = 0x0F100800;
            res->ecx = RETREC_CPUID_FEATURES_ECX;
            res->edx = 0x178BFBFF;
            break;

        case 0x80000000:
            res->eax = 0x80000008;
            res->ebx = 0x756E6547;
            res->ecx = 0x6C65746E;
            res->edx = 0x49656E69;
            break;

        case 0x80000001:
            res->eax = 0x000206C1;
            res->ebx = 0x00000000;
            res->ecx = 0x00000001;
            res->edx = 0x20100800;
            break;

        case 0x80000002:
            res->eax = 0x74736557;
            res->ebx = 0x6572656D;
            res->ecx = 0x36354520;
            res->edx = 0x4C2F7878;
            break;

        case 0x80000003:
            res->eax = 0x78783635;
            res->ebx = 0x3635582F;
            res->ecx = 0x28207878;
            res->edx = 0x6168654E;
            break;

        case 0x80000004:
            res->eax = 0x2D6D656C;
            res->ebx = 0x00002943;
            res->ecx = 0x00000000;
            res->edx = 0x00000000;
            break;

        case 0x80000005:
            res->eax = 0x01FF01FF;
            res->ebx = 0x01FF01FF;
            res->ecx = 0x40020140;
            res->edx = 0x40020140;
            break;

        case 0x80000006:
            res->eax = 0x00000000;
            res->ebx = 0x42004200;
            res->ecx = 0x02008140;
            res->edx = 0x00808140;
            break;

        case 0x80000008:
            res->eax = 0x00003028;
            res->ebx = 0x00000000;
            res->ecx = 0x00000000;
            res->edx = 0x00000000;
            break;

        default:
            pr_info("Unsupported CPUID func 0x%x,0x%x, returning all 0s.\n", func, subfunc);
            break;
    }
}
