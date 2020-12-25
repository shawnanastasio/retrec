#pragma once

#include <cstdint>
#include <cstddef>
#include <variant>
#include <optional>
#include <string>

/**
 * This is an x-macro that defines each supported cpu operation, along with a corresponding
 * `assembler` method that emits it. In cases where multiple methods can emit an instruction,
 * only the primary one is defined here.
 *
 * This macro is used later down to define the entries of the `Operation` enum. For this, only
 * the first field is actually used.
 */
#define PPC64LE_ENUMERATE_OPERATIONS(x) \
    x(ADD, assembler::add) \
    x(ADDI, assembler::addi) \
    x(ADDIS, assembler::addis) \
    x(ADDPCIS, assembler::addpcis) \
    x(AND, assembler::_and) \
    x(ANDI_, assembler::andi_) \
    x(B, assembler::b) \
    x(BC, assembler::bc) \
    x(BCCTR, assembler::bcctr) \
    x(CMP, assembler::cmp) \
    x(CMPI, assembler::cmpi) \
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
    x(LBZ, assembler::lbz) \
    x(LBZU, assembler::lbzu) \
    x(LBZUX, assembler::lbzux) \
    x(LBZX, assembler::lbzx) \
    x(LD, assembler::ld) \
    x(LDU, assembler::ldu) \
    x(LDUX, assembler::ldux) \
    x(LDX, assembler::ldx) \
    x(LHZ, assembler::lhz) \
    x(LHZU, assembler::lhzu) \
    x(LHZUX, assembler::lhzux) \
    x(LHZX, assembler::lhzx) \
    x(LWZ, assembler::lwz) \
    x(LWZU, assembler::lwzu) \
    x(LWZUX, assembler::lwzux) \
    x(LWZX, assembler::lwzx) \
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
    x(RLWIMI, assembler::rlwimi) \
    x(RLWINM, assembler::rlwinm) \
    x(SC, assembler::sc) \
    x(SLDI, assembler::sldi) \
    x(SRDI, assembler::srdi) \
    x(STB, assembler::stb) \
    x(STBU, assembler::stbu) \
    x(STBUX, assembler::stbux) \
    x(STBX, assembler::stbx) \
    x(STD, assembler::std) \
    x(STDU, assembler::stdu) \
    x(STDUX, assembler::stdux) \
    x(STDX, assembler::stdx) \
    x(STH, assembler::sth) \
    x(STHU, assembler::sthu) \
    x(STHUX, assembler::sthux) \
    x(STHX, assembler::sthx) \
    x(STW, assembler::stw) \
    x(STWU, assembler::stwu) \
    x(STWUX, assembler::stwux) \
    x(STWX, assembler::stwx) \
    x(SUB, assembler::sub) \
    x(SUBC, assembler::subc) \
    x(SUBE, assembler::sube) \
    x(XOR, assembler::_xor) \
    x(INVALID, assembler::invalid) \
    x(U32, assembler::u32)

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

// Annotated types for assembler operands. Allows inspection code (like relocation) to determine
// parameter uses without hardcoding table of per-instruction meanings.
//
// To ensure that the new types are distinct from their underlying types (for use in std::variant),
// they are declared as enums. A typedef/using declaration would allow implicit conversion and make
// it difficult to store the types in std::variants that can also contain the underlying type.
enum BI : uint8_t {};            // Branch CR field
enum AA : bool {};               // Branch absolute address toggle
enum LK : bool {};               // Branch linkage toggle
enum rel_off_26bit : int32_t {}; // 26-bit relative offset (e.g. B)
enum rel_off_16bit : int16_t {}; // 16-bit relative offset (e.g. BC)

class instruction_stream;

//
// Types used by codegen_ppc64le and related higher-level code
//

enum class LabelPosition {
    BEFORE,
    AFTER
};

struct relocation {
    // Fill in the relative offset to an absolute target virtual address
    struct imm_rel_vaddr_fixup { uint64_t vaddr; };

    // Helpers for declaring labels and referencing them
    struct imm_rel_label_fixup { std::string label_name; LabelPosition position; };
    struct declare_label { std::string label_name; };
    struct declare_label_after { std::string label_name; };

    // Emit a direct call to a given virtual address
    struct imm_rel_direct_call { uint64_t vaddr; };

    // Emit a direct jmp to a given virtual address
    struct imm_rel_direct_jmp { uint64_t vaddr; };

    using DataT = std::variant<imm_rel_vaddr_fixup, imm_rel_label_fixup, declare_label,
                               declare_label_after, imm_rel_direct_call, imm_rel_direct_jmp>;

    size_t insn_cnt; // Number of instructions reserved for this Relocation
    DataT data;      // Relocation-specific data
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
