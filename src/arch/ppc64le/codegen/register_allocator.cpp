#include <arch/ppc64le/codegen/register_allocator.h>

using namespace retrec;
using namespace retrec::ppc64le;

//
// X86_64 static allocation manager
//

register_allocator_x86_64::static_allocation_set register_allocator_x86_64::static_allocations;

register_allocator_x86_64::static_allocation_set::static_allocation_set() {
    for (size_t i=0; i<ARRAY_SIZE(allocations); i++)
        allocations[i] = GPR_INVALID;

    // Statically allocate some X86_64 registers to GPRs.
    // The static allocations try to match X86_64 SysV calling conventions
    // to ppc64le ELFv2 calling conventions to reduce the save/restore penalty when
    // foreign function calls or syscalls are made.
    //
    // Must be kept in sync with accessors in runtime_context_ppc64le.h
    allocations[reserved_index(llir::X86_64Register::RSP)] = 1;
    allocations[reserved_index(llir::X86_64Register::RDI)] = 3;
    allocations[reserved_index(llir::X86_64Register::RSI)] = 4;
    allocations[reserved_index(llir::X86_64Register::RDX)] = 5;
    allocations[reserved_index(llir::X86_64Register::RCX)] = 6;
    allocations[reserved_index(llir::X86_64Register::R8)]  = 7;
    allocations[reserved_index(llir::X86_64Register::R9)]  = 8;
    allocations[reserved_index(llir::X86_64Register::RAX)] = 9;

    allocations[reserved_index(llir::X86_64Register::R10)] = 16;
    allocations[reserved_index(llir::X86_64Register::R11)] = 17;
    allocations[reserved_index(llir::X86_64Register::R12)] = 18;
    allocations[reserved_index(llir::X86_64Register::R13)] = 19;
    allocations[reserved_index(llir::X86_64Register::R14)] = 20;
    allocations[reserved_index(llir::X86_64Register::R15)] = 21;
    allocations[reserved_index(llir::X86_64Register::RBX)] = 22;
    allocations[reserved_index(llir::X86_64Register::RBP)] = 23;
}

//
// X86_64 target register allocator
//

register_allocator_x86_64::register_allocator_x86_64(uint64_t start_vaddr_) : start_vaddr(start_vaddr_), end_vaddr(0) {
    for (size_t i=0; i<ARRAY_SIZE(gprs); i++)
        gprs[i] = { RegisterInfo::State::FREE };

    // Reserved static allocations
    gprs[1]  = {RegisterInfo::State::RESERVED};
    gprs[3]  = {RegisterInfo::State::RESERVED};
    gprs[4]  = {RegisterInfo::State::RESERVED};
    gprs[5]  = {RegisterInfo::State::RESERVED};
    gprs[6]  = {RegisterInfo::State::RESERVED};
    gprs[7]  = {RegisterInfo::State::RESERVED};
    gprs[8]  = {RegisterInfo::State::RESERVED};
    gprs[9]  = {RegisterInfo::State::RESERVED};
    gprs[16] = {RegisterInfo::State::RESERVED};
    gprs[17] = {RegisterInfo::State::RESERVED};
    gprs[18] = {RegisterInfo::State::RESERVED};
    gprs[19] = {RegisterInfo::State::RESERVED};
    gprs[20] = {RegisterInfo::State::RESERVED};
    gprs[21] = {RegisterInfo::State::RESERVED};
    gprs[22] = {RegisterInfo::State::RESERVED};
    gprs[23] = {RegisterInfo::State::RESERVED};

    // Store pointer to runtime_context in R11
    gprs[11] = {RegisterInfo::State::RESERVED};

    // Flag lazy evaluation registers
    gprs[12] = {RegisterInfo::State::RESERVED};
    gprs[13] = {RegisterInfo::State::RESERVED};
    gprs[14] = {RegisterInfo::State::RESERVED};
}

register_allocator_x86_64::~register_allocator_x86_64() {
}

gpr_t register_allocator_x86_64::allocate_gpr() {
    for (gpr_t i=1 /* skip GPR0 which is sometimes useless */; i<ARRAY_SIZE(gprs); i++) {
        if (gprs[i].state == RegisterInfo::State::FREE) {
            gprs[i].state = RegisterInfo::State::ALLOCATED;
            return i;
        }
    }

    return GPR_INVALID; // No free registers
}

gpr_t register_allocator_x86_64::get_fixed_gpr(const llir::Register &reg) {
    gpr_t ret = static_allocations.allocations[static_allocations.reserved_index(reg)];
    assert(ret != GPR_INVALID);
    return ret;
}

void register_allocator_x86_64::free_gpr(gpr_t gpr) {
    assert(gpr != GPR_INVALID);
    if (gprs[gpr].state == RegisterInfo::State::RESERVED)
        return;
    assert(gprs[gpr].state == RegisterInfo::State::ALLOCATED);
    gprs[gpr].state = RegisterInfo::State::FREE;
}

