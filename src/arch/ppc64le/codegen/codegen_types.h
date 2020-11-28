#pragma once

#include <cstdint>
#include <cstddef>
#include <variant>
#include <optional>

/**
 * This is an x-macro that defines each supported cpu operation, along with a corresponding
 * `assembler` method that emits it. In cases where multiple methods can emit an instruction,
 * only the primary one is defined here.
 *
 * This macro is used later down to define the entries of the `Operation` enum. For this, only
 * the first field is actually used.
 */
#define PPC64LE_ENUMERATE_OPERATIONS(x) \
    x(ADD, assembler::add_internal) \
    x(ADDI, assembler::addi) \
    x(ADDIS, assembler::addis) \
    x(ADDPCIS, assembler::addpcis) \
    x(AND, assembler::_and) \
    x(ANDI_, assembler::andi_) \
    x(B, assembler::b_internal) \
    x(BC, assembler::bc_internal) \
    x(BCCTR, assembler::bcctr_internal) \
    x(CMPI, assembler::cmpi) \
    x(CMP, assembler::cmp) \
    x(CMPL, assembler::cmpl) \
    x(CMPLI, assembler::cmpli) \
    x(CRAND, assembler::crand) \
    x(CRANDC, assembler::crandc) \
    x(CREQV, assembler::creqv) \
    x(CRNAND, assembler::crnand) \
    x(CRNOR, assembler::crnor) \
    x(CROR, assembler::cror) \
    x(CRORC, assembler::crorc) \
    x(CRXOR, assembler::crxor) \
    x(EQV, assembler::creqv) \
    x(EXTSB, assembler::extsb) \
    x(EXTSH, assembler::extsh) \
    x(MCRF, assembler::mcrf) \
    x(MCRXRX, assembler::mcrxrx) \
    x(MFCR, assembler::mfcr) \
    x(MFOCRF, assembler::mfocrf) \
    x(MFSPR, assembler::mfspr) \
    x(MTCRF, assembler::mtcrf) \
    x(MTOCRF, assembler::mtocrf) \
    x(MTSPR, assembler::mtspr) \
    x(NEG, assembler::neg) \
    x(OR, assembler::_or) \
    x(ORI, assembler::ori) \
    x(ORIS, assembler::oris) \
    x(RLDCL, assembler::rldcl) \
    x(RLDICL, assembler::rldicl) \
    x(RLDICR, assembler::rldicr) \
    x(RLDIMI, assembler::rldimi) \
    x(RLWINM, assembler::rlwinm) \
    x(SC, assembler::sc) \
    x(SLDI, assembler::sldi) \
    x(SRDI, assembler::srdi) \
    x(STD, assembler::std) \
    x(SUB, assembler::sub) \
    x(SUBC, assembler::subc) \
    x(SUBE, assembler::sube) \
    x(XOR, assembler::_xor) \
    x(INVALID, assembler::invalid)

namespace retrec {

namespace ppc64le {

constexpr int INSN_SIZE = 4; // ISA 3.1 be damned

//
// Types used by the assembler and related code
//

class assembler;

// A list of all Operation types. See PPC64LE_ENUMERATE_OPERATIONS above.
enum class Operation {
#define OPERATION(op, ...) op,
    PPC64LE_ENUMERATE_OPERATIONS(OPERATION)
#undef OPERATION
    SIZE
};

// A list of strings for all Operation types
extern const char *operation_names[(std::underlying_type_t<Operation>)Operation::SIZE];

enum class BO : uint8_t {
    ALWAYS = 0b10100,    // Branch unconditionally
    FIELD_CLR = 0b00100, // Branch if given CR field is clear (0)
    FIELD_SET = 0b01100  // Branch if given CR Field is set (1)
};

enum class SPR : uint16_t {
    XER = 1,
    DSCR = 3,
    LR = 8,
    CTR = 9
};

class instruction_stream;

//
// Types used by codegen_ppc64le and related higher-level code
//

struct relocation {
    struct imm_rel_vaddr_fixup { uint64_t abs_vaddr; };

    size_t insn_cnt; // Number of instructions reserved for this Relocation
    std::variant<imm_rel_vaddr_fixup> data;
};

// Auxiliary data that can be attached to an instruction stream entry
struct instruction_aux {
    bool always_keep; // Whether we should never let this instruction be optimized away
    std::optional<ppc64le::relocation> relocation;

    instruction_aux(bool always_keep_, decltype(relocation) relocation_)
        : always_keep(always_keep_), relocation(std::move(relocation_)) {}
};

// Guaranteed to hold an immediate relative offset
using rel_off_t = int32_t;

}; // namespace ppc64le

}; // namespace retrec
