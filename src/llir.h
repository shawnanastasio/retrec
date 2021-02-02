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
#include <util/magic.h>
#include <util/staticvector.h>

#include <array>
#include <functional>
#include <string>
#include <type_traits>
#include <variant>
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
        PPC64Register ppc64;
    };

    enum class Mask {
        // 64-bit GPR masks
        LowLowLow8,  // 7 downto 0
        LowLowHigh8, // 15 downto 8
        LowLow16,    // 15 downto 0
        Low32,       // 31 downto 0
        Full64,      // 63 downto 0

        // 128-bit vector masks
        Vector128Full,   // 127 downto 0
        Vector128High64, // 127 downto 64
        Vector128Low64,  // 63 downto 0
        Vector128Low32,  // 31 downto 0

        Special
    } mask {};

    // Whether or not to zero bits not covered by mask on any write to this register
    bool zero_others { false };

    // A hint for the type of data stored in this register. This may be useful for optimizing
    // SIMD/vector loads/stores depending on whether integer or floating point calculations
    // are being performed.
    // See: https://stackoverflow.com/questions/6678073/difference-between-movdqa-and-movaps-x86-instructions
    //
    // These are specifically hints and MAY NOT modify functional behavior in any way.
    enum class TypeHint {
        NONE,
        FLOAT,
        DOUBLE,
        INT,
    } type_hint {};
};

// Architecture-specific operand definitions
#include <arch/x86_64/llir/llir_operands_x86_64.h>
class MemOp {
#   define LLIR_ENUMERATE_MEMOP_TYPES(x) \
        /* Parameters are: type, accessor_name, enum_value */ \
        x(X86_64MemOp, x86_64, X86_64)
    MAGIC_VARIANT_DECLARE(LLIR_ENUMERATE_MEMOP_TYPES)
public:
    // Accessors for underlying enum discriminator
    using Architecture = VariantEnumT;
    Architecture arch() const { return variant_enum_val; }

    // Specify whether the memory source register is updated with the newly
    // calculated address.
    enum class Update {
        NONE, // Perform no update
        PRE,  // Update source register with offset before dereferencing
        POST  // Update source register with offset after dereferencing
    } update {};
};

#undef LLIR_ALLOW_INTERNAL_INCLUDE

enum class Extension {
    NONE, // Do not perform extension
    SIGN, // Perform sign extension
    ZERO, // Perofmr zero extension
};

//
// LoadStore
//
struct LoadStore {
    enum class Op {
        INVALID,

        // GPR load/store/address instructions
        LOAD,
        STORE,
        LEA,

        // Vector load/store instructions
        VECTOR_LOAD,
        VECTOR_STORE,
    } op {};

    // Whether to perform sign extension
    Extension extension {};

    // Whether the destination/source operands must be aligned
    bool require_alignment { false };

    // Hint indicating whether this will be the last access to this address for a while.
    bool last_access_hint { false };
};

//
// Alu
//
struct Alu {
    enum class Op {
#   define LLIR_ENUMERATE_ALU_OPS(x) \
        x(INVALID) \
        /* Standard ALU operations */ \
        x(ADD) \
        x(AND) \
        x(IMUL) \
        x(MUL) \
        x(OR) \
        x(SAR) \
        x(SETCC) \
        x(SHL) \
        x(SHR) \
        x(SUB) \
        x(XOR) \
        x(LOAD_IMM) \
        x(MOVE_REG) \
        x(NOP) \
        x(SETFLAG) /* setflag - set the single flag in flags_modified to '1' */ \
        x(CLRFLAG) /* clrflag - set the single flag in flags_modified to '0' */ \
        /* Vector ALU operations */ \
        x(MOVE_VECTOR_REG) \
        /* Special/architecture-specific ops */ \
        x(X86_CPUID)
        LLIR_ENUMERATE_ALU_OPS(X_LIST)
    } op {};

    bool modifies_flags { false };

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
        DIRECTION,

        COUNT
    };

    // Extension type, if any
    Extension extension {};

    // Container for a contiguous, static, 0-delimited array of Flag values
    using FlagArr = StaticVector<Flag, (size_t)Flag::COUNT-1>;

    // Flags modified by this operation
    FlagArr flags_modified {};

    // Flags cleared (set to 0) unconditionally by this operation
    FlagArr flags_cleared {};

    // Flags that will be left in an undefined state after this operation
    FlagArr flags_undefined {};

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
#   define LLIR_ENUMERATE_BRANCH_OPS(x) \
        x(INVALID) \
        x(UNCONDITIONAL) \
        x(EQ) \
        x(NOT_EQ) \
        x(NEGATIVE) \
        x(NOT_NEGATIVE) \
        x(POSITIVE) \
        x(CARRY) \
        x(NOT_CARRY) \
        x(OVERFLOW) \
        x(NOT_OVERFLOW) \
        x(X86_ABOVE)      /* !CF && !ZF */ \
        x(X86_BELOW_EQ)   /* CF || ZF */ \
        x(X86_GREATER_EQ) /* SF == OF */ \
        x(X86_LESS)       /* SF != OF */ \
        x(X86_GREATER)    /* !ZF && (SF == OF) */  \
        x(X86_LESS_EQ)    /* ZF || (SF != OF) */
        LLIR_ENUMERATE_BRANCH_OPS(X_LIST)
    } op {};

    enum class Target {
        INVALID,
        RELATIVE,
        ABSOLUTE,
    } target {};

    // Whether or not the branch should store the next Instruction Pointer in the destination operand
    bool linkage { false };
};

//
// Interupt
//
struct Interrupt {
    enum class Op {
        INVALID,
        SYSCALL,
        ILLEGAL,
    } op {};
};

//
// Top level
//

class Operand {
    /**
     * Declare a variant+enum pair with accessorsfor operand types.
     * This lets us visit the underlying types using switch statements
     * on the enum while keeping the type safety of std::variant.
     */
#   define LLIR_ENUMERATE_OPERAND_TYPES(x) \
        /* Parameters are: type, accessor_name, enum_value */ \
        x(Register, reg, REG) \
        x(int64_t, imm, IMM) \
        x(MemOp, memory, MEM) \
        x(Branch::Op, branchop, BRANCHOP)
    MAGIC_VARIANT_DECLARE(LLIR_ENUMERATE_OPERAND_TYPES)
public:
    using Type = VariantEnumT;
    Type type() const { return variant_enum_val; }

    enum class Width {
        INVALID,
        _128BIT,
        _64BIT,
        _32BIT,
        _16BIT,
        _8BIT
    } width {};
};

// A qualification that can be specified with an Insn to change its behavior
class Qualification {
public:
    // Repeat the instruction that this Qualification is attached to until at least
    // one of the exit conditions is met.
    struct Repeat {
        // Condition that must be satisfied for loop to exit
        struct ExitCondition {
            // Exit if a flag is set/unset
            struct Condition {
                Branch::Op condition { Branch::Op::INVALID };
            };

            // Exit if a register is empty
            struct RegisterEmpty { Register reg; };

            enum class EvaluationOrder {
                INVALID,
                BEFORE, // Evaluate the condition before the instruction in the loop body (whlie)
                AFTER   // Evaluate the condition after the instruction in the loop body (do while)
            } evaluation_order { EvaluationOrder::INVALID };
            std::optional<std::variant<Condition, RegisterEmpty>> cond;
        };

        // Executed at the end of each loop iteration
        struct Update {
            struct RegisterDecrement { Register reg; };

            std::optional<std::variant<RegisterDecrement>> action;
        };

        std::array<ExitCondition, 2> exit_conditions {};
        Update update;
    };

    // Only execute the instruction that this Qualification is attached to if the condition is met
    struct Predicate {
        Branch::Op condition { Branch::Op::INVALID };
    };

    // Flags that can affect how the instruction accesses memory
    struct MemoryAttribute {
        bool atomic { false };
    };

private:
#   define LLIR_ENUMERATE_PREFIX_TYPES(x) \
        /* Parameters are: type, accessor_name, enum_value */ \
        x(Repeat, repeat, REPEAT) \
        x(Predicate, predicate, PREDICATE) \
        x(MemoryAttribute, memory_attribute, MEMORY_ATTRIBUTE)
    MAGIC_VARIANT_DECLARE(LLIR_ENUMERATE_PREFIX_TYPES)
public:
    // Qualification operation enum
    using Type = VariantEnumT;
    Type type() const { return variant_enum_val; }
};

class Insn {
    /**
     * Declare a variant+enum pair with accessors for instruction classes.
     */
#   define LLIR_ENUMERATE_INSN_CLASSES(x) \
        /* Parameters are: type, accessor_name, enum_value */ \
        x(LoadStore, loadstore, LOADSTORE) \
        x(Alu, alu, ALU) \
        x(Branch, branch, BRANCH) \
        x(Interrupt, interrupt, INTERRUPT)
    MAGIC_VARIANT_DECLARE(LLIR_ENUMERATE_INSN_CLASSES)
public:
    // Address of original instruction
    uint64_t address;

    // Size in bytes of original instruction
    uint16_t size;

    // Instruction class enum
    using Class = VariantEnumT;
    Class iclass() const { return variant_enum_val; }

    // Operands
    std::array<Operand, 2> dest {};
    std::array<Operand, 2> src {};

    // Optional instruction qualifications that can modify its behavior
    std::array<Qualification, 2> qualifications;

    // Array sizes
    uint8_t dest_cnt { 0 };
    uint8_t src_cnt { 0 };
    uint8_t qualification_count { 0 };
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
    }
    ASSERT_NOT_REACHED();
}

template<>
inline std::string to_string(const LoadStore &loadstore) {
    std::string ret = "";
    switch (loadstore.op) {
        case LoadStore::Op::LOAD: ret += "LOAD("; break;
        case LoadStore::Op::STORE: ret += "STORE("; break;
        case LoadStore::Op::LEA: ret += "LEA("; break;
        case LoadStore::Op::VECTOR_LOAD: ret += "VECTOR_LOAD("; break;
        case LoadStore::Op::VECTOR_STORE: ret += "VECTOR_STORE("; break;
        case LoadStore::Op::INVALID: ASSERT_NOT_REACHED();
    }

    ret += "ext=";
    switch (loadstore.extension) {
        case Extension::NONE: ret += "NONE"; break;
        case Extension::ZERO: ret += "ZERO"; break;
        case Extension::SIGN: ret += "SIGN"; break;
    }
    ret += ")";
    return ret;
}

template<>
inline std::string to_string(const Alu &alu) {
    switch (alu.op) {
#define enum_name(x) case Alu::Op::x: return #x;
        LLIR_ENUMERATE_ALU_OPS(enum_name)
#undef enum_name
    }
    ASSERT_NOT_REACHED();
}

template<>
inline std::string to_string(const Branch::Op &branchop) {
    switch (branchop) {
#define add_enum_name(x) case Branch::Op::x: return #x; break;
        LLIR_ENUMERATE_BRANCH_OPS(add_enum_name)
#undef add_enum_name
    }
    ASSERT_NOT_REACHED();
}

template <>
inline std::string to_string(const Branch &branch) {
    std::string ret = to_string(branch.op) + ", ";

    switch (branch.target) {
        case Branch::Target::RELATIVE: ret += "RELATIVE"; break;
        case Branch::Target::ABSOLUTE: ret += "ABSOLUTE"; break;
        case Branch::Target::INVALID: ASSERT_NOT_REACHED();
    }

    return ret;
}

template<>
inline std::string to_string(const Interrupt &interrupt) {
    switch (interrupt.op) {
        case Interrupt::Op::SYSCALL: return "SYSCALL";
        case Interrupt::Op::ILLEGAL: return "ILLEGAL";
        case Interrupt::Op::INVALID: ASSERT_NOT_REACHED();
    }
    ASSERT_NOT_REACHED();
}

template<>
inline std::string to_string(const X86_64Register &reg) {
    switch (reg) {
#define declare_case(x) case llir::X86_64Register::x: return #x;
        LLIR_ENUMERATE_X86_64_REGISTERS(declare_case)
#undef declare_case
    }
    ASSERT_NOT_REACHED();
}

template<>
inline std::string to_string(const Register::Mask &mask) {
    switch (mask) {
        case Register::Mask::Full64: return "Full64";
        case Register::Mask::Low32: return "Low32";
        case Register::Mask::LowLow16: return "LowLow16";
        case Register::Mask::LowLowHigh8: return "LowLowHigh8";
        case Register::Mask::LowLowLow8: return "LowLowLow8";
        case Register::Mask::Vector128Full: return "Vector128Full";
        case Register::Mask::Vector128High64: return "Vector128High64";
        case Register::Mask::Vector128Low64: return "Vector128Low64";
        case Register::Mask::Vector128Low32: return "Vector128Low32";
        case Register::Mask::Special: return "Special";
    }
    ASSERT_NOT_REACHED();
}

template<>
inline std::string to_string(const Register &reg) {
    switch (reg.arch) {
        case Architecture::X86_64:
            return to_string(reg.x86_64) + "(" + to_string(reg.mask) + ")";
        case Architecture::ppc64le: TODO();
    }
    ASSERT_NOT_REACHED();
}

template<>
inline std::string to_string(const MemOp &memop) {
    std::string ret;
    switch (memop.arch()) {
        case MemOp::Architecture::X86_64:
            ret =  "Segment=" + to_string(memop.x86_64().segment) +
                   " Base=" + to_string(memop.x86_64().base) +
                   " Index=" + to_string(memop.x86_64().index) +
                   " Scale=" + std::to_string(memop.x86_64().scale) +
                   " Disp=" + std::to_string(memop.x86_64().disp);
            break;
    }

    ret += " update=";
    switch (memop.update) {
        case MemOp::Update::NONE: ret += "NONE"; break;
        case MemOp::Update::PRE: ret += "PRE"; break;
        case MemOp::Update::POST: ret += "POST"; break;
    }

    return ret;
}

template<>
inline std::string to_string(const Operand &operand) {
    std::string ret;
    switch (operand.type()) {
        case Operand::Type::IMM: ret += "Immediate=" + std::to_string((int64_t)operand.imm()); break;
        case Operand::Type::MEM: ret += "Memory("+ to_string(operand.memory()) + ")"; break;
        case Operand::Type::REG: ret += "Reg=" + to_string(operand.reg()); break;
        case Operand::Type::BRANCHOP: ret += "Branchop=" + to_string(operand.branchop()); break;
    }
    ret += ",width=";
    switch (operand.width) {
        case Operand::Width::_128BIT: ret += "128"; break;
        case Operand::Width::_64BIT: ret += "64"; break;
        case Operand::Width::_32BIT: ret += "32"; break;
        case Operand::Width::_16BIT: ret += "16"; break;
        case Operand::Width::_8BIT: ret += "8"; break;
        case Operand::Width::INVALID: ret += "INVALID"; break;
    }
    return ret;
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
            case Alu::Flag::DIRECTION: ret += "DIRECTION"; break;
            case Alu::Flag::INVALID: break;
            case Alu::Flag::COUNT: break;
        }
        if (i != flags.size() - 1)
            ret += ", ";
    }

    return ret;
}

template<>
inline std::string to_string(const Qualification &qual) {
    std::string ret;

    // FIXME: make this more useful
    switch (qual.type()) {
        case Qualification::Type::REPEAT:
            ret += "Repeat";
            break;
        case Qualification::Type::PREDICATE:
            ret += "Predicate";
            break;
        case Qualification::Type::MEMORY_ATTRIBUTE:
            ret += "MemoryAttribute";
            break;
    }

    return ret;
}

template<>
inline std::string to_string(const Insn &insn) {
    std::string ret = "(";
    ret += "Class=" + to_string(insn.iclass());
    switch (insn.iclass()) {
        case Insn::Class::LOADSTORE:
            ret += " Op=" + to_string(insn.loadstore()); break;
        case Insn::Class::ALU:
            ret += " Op=" + to_string(insn.alu());
            if (insn.alu().modifies_flags) {
                ret += " FlagsModified(" + to_string(insn.alu().flags_modified) + ")";
                ret += " FlagsCleared(" + to_string(insn.alu().flags_cleared) + ")";
                ret += " FlagsUndefined(" + to_string(insn.alu().flags_undefined) + ")";
            }
            break;
        case Insn::Class::BRANCH:
            ret += " Op=" + to_string(insn.branch()); break;
        case Insn::Class::INTERRUPT:
            ret += " Op=" + to_string(insn.interrupt()); break;
    }
    for (size_t i=0; i<insn.dest_cnt; i++)
        ret += " Destination(" + to_string(insn.dest[i]) + ")";
    for (size_t i=0; i<insn.src_cnt; i++)
        ret += " Source" + std::to_string(i) + "(" + to_string(insn.src[i]) + ")";
    for (size_t i=0; i<insn.qualification_count; i++)
        ret += "Qualification(" + to_string(insn.qualifications[i]) + ")";
    return ret + ")";
}

} // namespace llir
} // namespace retrec
