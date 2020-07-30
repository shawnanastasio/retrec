#pragma once

#include <util.h>

#include <string>
#include <cstdint>

namespace retrec {
namespace llir {

//
// Arch-dependent
//


#define LLIR_ALLOW_INTERNAL_INCLUDE

// Architecture-specific register definitions
#include <arch/x86_64/llir/llir_registers_x86_64.h>
#include <arch/ppc64le/llir/llir_registers_ppc64le.h>
struct Register {
    Architecture arch;
    union {
        X86_64Register x86_64;
    };

    enum class Mask {
        Full64,      // 63 downto 0
        Low32,       // 31 downto 0
        LowLow16,    // 15 downto 0
        LowLowHigh8, // 15 downto 8
        LowLowLow8,  // 7 downto 0

        Special
    } mask;

    // Whether or not to zero bits not covered by mask on any write to this register
    bool zero_others;
};

// Architecture-specific operand definitions
#include <arch/x86_64/llir/llir_operands_x86_64.h>
struct MemOp {
    Architecture arch;
    union {
        X86_64MemOp x86_64;
    };
};

#undef LLIR_ALLOW_INTERNAL_INCLUDE

//
// LoadStore
//
struct LoadStore {
    enum class Op {
        LOAD,
        STORE,
    } op;
};

//
// Alu
//
struct Alu {
    enum class Op {
        ADD,
        SUB,
        MULT,
        LOAD_IMM,
    } op;
};

//
// Branch
//
struct Branch {
    enum class Op {
        UNCONDITIONAL,
    } op;

    enum class Target {
        RELATIVE,
    } target;
};

//
// Interupt
//
struct Interrupt {
    enum class Op {
        SYSCALL,
    } op;
};

//
// Top level
//

struct Operand {
    enum class Type {
        REG,
        IMM,
        MEM
    } type;
    union {
        Register reg;
        int64_t imm;
        MemOp memory;
    };
};

struct Insn {
    // Address of original instruction
    uint64_t address;

    // Instruction class + class-specific data
    enum class Class {
        LOADSTORE,
        ALU,
        BRANCH,
        INTERRUPT,
    } iclass;
    union {
        LoadStore loadstore;
        Alu alu;
        Branch branch;
        Interrupt interrupt;
    };

    uint8_t dest_cnt;
    Operand dest[1];
    uint8_t src_cnt;
    Operand src[2];
};

//
// Helpers
//

template<typename T>
std::string to_string(const T &data) {
    return std::to_string(data);
}

template<>
inline std::string to_string(const Insn::Class &iclass) {
    switch (iclass) {
        case Insn::Class::LOADSTORE: return "Load/Store";
        case Insn::Class::ALU: return "ALU";
        case Insn::Class::BRANCH: return "Branch";
        case Insn::Class::INTERRUPT: return "Interrupt";
        default:
            TODO();
    }
}

template<>
inline std::string to_string(const LoadStore &loadstore) {
    switch (loadstore.op) {
        case LoadStore::Op::LOAD: return "LOAD";
        case LoadStore::Op::STORE: return "STORE";
        default:
            TODO();
    }
}

template<>
inline std::string to_string(const Alu &alu) {
    switch (alu.op) {
        case Alu::Op::ADD: return "ADD";
        case Alu::Op::SUB: return "SUB";
        case Alu::Op::MULT: return "MULT";
        case Alu::Op::LOAD_IMM: return "LOAD_IMM";
        default:
            TODO();
    }
}

template <>
inline std::string to_string(const Branch &branch) {
    std::string ret = "";
    switch (branch.op) {
        case Branch::Op::UNCONDITIONAL: ret += "UNCONDITIONAL,"; break;
        default:
            TODO();
    }

    switch (branch.target) {
        case Branch::Target::RELATIVE: ret += "RELATIVE"; break;
        default:
            TODO();
    }

    return ret;
}

template<>
inline std::string to_string(const Interrupt &interrupt) {
    switch (interrupt.op) {
        case Interrupt::Op::SYSCALL: return "SYSCALL";
        default:
            TODO();
    }
}

template<>
inline std::string to_string(const X86_64Register &reg) {
    switch (reg) {
        case llir::X86_64Register::INVALID: return "INVALID";
        case llir::X86_64Register::RAX: return "RAX";
        case llir::X86_64Register::RBX: return "RBX";
        case llir::X86_64Register::RCX: return "RCX";
        case llir::X86_64Register::RDX: return "RDX";
        case llir::X86_64Register::RSP: return "RSP";
        case llir::X86_64Register::RBP: return "RBP";
        case llir::X86_64Register::RSI: return "RSI";
        case llir::X86_64Register::RDI: return "RDI";
        case llir::X86_64Register::R8: return "R8";
        case llir::X86_64Register::R9: return "R9";
        case llir::X86_64Register::R10: return "R10";
        case llir::X86_64Register::R11: return "R11";
        case llir::X86_64Register::R12: return "R12";
        case llir::X86_64Register::R13: return "R13";
        case llir::X86_64Register::R14: return "R14";
        case llir::X86_64Register::R15: return "R15";
        case llir::X86_64Register::RIP: return "RIP";
        case llir::X86_64Register::FS: return "FS";
        case llir::X86_64Register::GS: return "GS";
        case llir::X86_64Register::CS: return "CS";
        case llir::X86_64Register::SS: return "SS";
        case llir::X86_64Register::DS: return "DS";
        case llir::X86_64Register::ES: return "ES";
        default:
            TODO();
    }
}

template<>
inline std::string to_string(const Register::Mask &mask) {
    switch(mask) {
        case Register::Mask::Full64: return "Full64";
        case Register::Mask::Low32: return "Low32";
        case Register::Mask::LowLow16: return "LowLow16";
        case Register::Mask::LowLowHigh8: return "LowLowHigh8";
        case Register::Mask::LowLowLow8: return "LowLowLow8";
        case Register::Mask::Special: return "Special";
        default:
            TODO();
    }
}

template<>
inline std::string to_string(const Register &reg) {
    switch (reg.arch) {
        case Architecture::X86_64:
            return to_string(reg.x86_64) + "(" + to_string(reg.mask) + ")";
        default:
            TODO();
    }
}

template<>
inline std::string to_string(const MemOp &memop) {
    switch (memop.arch) {
        case Architecture::X86_64:
            return "Segment=" + to_string(memop.x86_64.segment) +
                   " Base=" + to_string(memop.x86_64.base) +
                   " Index= " + to_string(memop.x86_64.index) +
                   " Scale= " + std::to_string(memop.x86_64.scale) +
                   " Disp= " + std::to_string(memop.x86_64.disp);
        default:
            TODO();
    }
}

template<>
inline std::string to_string(const Operand &operand) {
    switch (operand.type) {
        case Operand::Type::IMM: return std::string("Immediate=") + std::to_string(operand.imm);
        case Operand::Type::MEM: return std::string("Memory=") + to_string(operand.memory);
        case Operand::Type::REG: return std::string("Reg=") + to_string(operand.reg);
        default:
            TODO();
    }
}

template<>
inline std::string to_string(const Insn &insn) {
    std::string ret = "(";
    ret += "Class=" + to_string(insn.iclass);
    switch (insn.iclass) {
        case Insn::Class::LOADSTORE:
            ret += " Op=" + to_string(insn.loadstore); break;
        case Insn::Class::ALU:
            ret += " Op=" + to_string(insn.alu); break;
        case Insn::Class::BRANCH:
            ret += " Op=" + to_string(insn.branch); break;
        case Insn::Class::INTERRUPT:
            ret += " Op=" + to_string(insn.interrupt); break;
        default:
            TODO();
    }
    for (size_t i=0; i<insn.dest_cnt; i++)
        ret += " Destination(" + to_string(insn.dest[0]) + ")";
    for (size_t i=0; i<insn.src_cnt; i++)
        ret += " Source" + std::to_string(i) + "(" + to_string(insn.src[i]) + ")";
    return ret + ")";
}

} // namespace llir
} // namespace retrec