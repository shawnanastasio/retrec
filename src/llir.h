#pragma once

#include <util/util.h>

#include <functional>
#include <type_traits>
#include <string>
#include <array>
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
        LowLowLow8,  // 7 downto 0
        LowLowHigh8, // 15 downto 8
        LowLow16,    // 15 downto 0
        Low32,       // 31 downto 0
        Full64,      // 63 downto 0

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
        LEA,
    } op;

    bool sign_extension;
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

    bool modifies_flags;

    /**
     * This serves as a superset of all flags in supported llir architectures.
     * There may be a better way to represent this on a per-arch basis, but this
     * works for now.
     */
    enum class Flag {
        INVALID,

        CARRY,
        PARITY,
        AUXILIARY_CARRY,
        ZERO,
        SIGN,
        OVERFLOW,

        COUNT
    };
    using FlagArr = std::array<Flag, (size_t)Flag::COUNT-1>;

    static void IterateFlags(const FlagArr &flags, std::function<void(Flag)> cb) {
        for (size_t i = 0; i < flags.size() && flags[i] != llir::Alu::Flag::INVALID; i++)
            cb(flags[i]);
    }

    // Flags modified by this operation,
    FlagArr flags_modified;

    static constexpr FlagArr all_flags = {
        Flag::CARRY, Flag::PARITY, Flag::AUXILIARY_CARRY, Flag::ZERO,
        Flag::SIGN, Flag::OVERFLOW
    };
};

//
// Branch
//
struct Branch {
    enum class Op {
        UNCONDITIONAL,
        EQ,
        NOT_EQ,
        NEGATIVE,
        NOT_NEGATIVE,
        POSITIVE,
        CARRY,
        NOT_CARRY,
        OVERFLOW,
        NOT_OVERFLOW,

        X86_ABOVE,      // !CF && !ZF
        X86_BELOW_EQ,   // CF || ZF
        X86_GREATER_EQ, // SF == OF
        X86_LESS,       // SF != OF
        X86_GREATER,    // !ZF && (SF == OF)
        X86_LESS_EQ,    // ZF || (SF != OF)
    } op;

    enum class Target {
        RELATIVE,
        ABSOLUTE,
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

    enum class Width {
        _64BIT,
        _32BIT,
        _16BIT,
        _8BIT
    } width;
};

struct Insn {
    // Address of original instruction
    uint64_t address;

    // Size in bytes of original instruction
    uint16_t size;

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
static_assert(std::is_trivial_v<Insn>, "Insn must be trivial!");

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
        case LoadStore::Op::LEA: return "LEA";
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
        case Branch::Op::EQ: ret += "EQ,"; break;
        case Branch::Op::NOT_EQ: ret += "!EQ,"; break;
        case Branch::Op::NEGATIVE: ret += "NEGATIVE,"; break;
        case Branch::Op::NOT_NEGATIVE: ret += "!NEGATIVE,"; break;
        case Branch::Op::POSITIVE: ret += "POSITIVE,"; break;
        case Branch::Op::CARRY: ret += "CARRY,"; break;
        case Branch::Op::NOT_CARRY: ret += "NOT_CARRY,"; break;
        case Branch::Op::OVERFLOW: ret += "OVERFLOW,"; break;
        case Branch::Op::NOT_OVERFLOW: ret += "NOT_OVERFLOW,"; break;
        case Branch::Op::X86_ABOVE: ret += "X86_ABOVE,"; break;
        case Branch::Op::X86_BELOW_EQ: ret += "X86_BELOW_EQ,"; break;
        case Branch::Op::X86_GREATER_EQ: ret += "X86_GREATER_EQ,"; break;
        case Branch::Op::X86_LESS: ret += "X86_LESS,"; break;
        case Branch::Op::X86_GREATER: ret += "X86_GREATER,"; break;
        case Branch::Op::X86_LESS_EQ: ret += "X86_LESS_EQ,"; break;
        default:
            TODO();
    }

    switch (branch.target) {
        case Branch::Target::RELATIVE: ret += "RELATIVE"; break;
        case Branch::Target::ABSOLUTE: ret += "ABSOLUTE"; break;
        default:
            TODO();
    }

    return ret;
}

template<>
inline std::string to_string(const Interrupt &interrupt) {
    switch (interrupt.op) {
        case Interrupt::Op::SYSCALL: return "SYSCALL";
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
                   " Index=" + to_string(memop.x86_64.index) +
                   " Scale=" + std::to_string(memop.x86_64.scale) +
                   " Disp=" + std::to_string(memop.x86_64.disp);
        default:
            TODO();
    }
}

template<>
inline std::string to_string(const Operand &operand) {
    switch (operand.type) {
        case Operand::Type::IMM: return std::string("Immediate=") + std::to_string((int64_t)operand.imm);
        case Operand::Type::MEM: return std::string("Memory(") + to_string(operand.memory) + ")";
        case Operand::Type::REG: return std::string("Reg=") + to_string(operand.reg);
        default:
            TODO();
    }
}

template <>
inline std::string to_string(const decltype(Alu::flags_modified) &flags) {
    std::string ret;
    for (size_t i = 0; i < flags.size(); i++) {
        switch (flags[i]) {
            case Alu::Flag::CARRY: ret += "Carry"; break;
            case Alu::Flag::PARITY: ret += "Parity"; break;
            case Alu::Flag::AUXILIARY_CARRY: ret += "AuxCarry"; break;
            case Alu::Flag::ZERO: ret += "Zero"; break;
            case Alu::Flag::SIGN: ret += "Sign"; break;
            case Alu::Flag::OVERFLOW: ret += "Overflow"; break;
            case Alu::Flag::INVALID: break;
            default: TODO();
        }
        if (i != flags.size() - 1)
            ret += ", ";
    }

    return ret;
}

template<>
inline std::string to_string(const Insn &insn) {
    std::string ret = "(";
    ret += "Class=" + to_string(insn.iclass);
    switch (insn.iclass) {
        case Insn::Class::LOADSTORE:
            ret += " Op=" + to_string(insn.loadstore); break;
        case Insn::Class::ALU:
            ret += " Op=" + to_string(insn.alu);
            if (insn.alu.modifies_flags)
                ret += " FlagsModified(" + to_string(insn.alu.flags_modified) + ")";
            break;
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
