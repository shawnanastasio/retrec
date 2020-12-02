#pragma once

#include <util/util.h>
#include <util/magic.h>
#include <arch/ppc64le/codegen/codegen_types.h>
#include <allocators.h>
#include <instruction_stream.h>

#include <vector>
#include <functional>
#include <utility>
#include <cstddef>
#include <cstdint>

// Comment out to disable log spam
#define ASM_LOG(...) pr_debug(__VA_ARGS__)

#ifndef ASM_LOG
#define ASM_LOG(...)
#endif

namespace retrec {

namespace ppc64le {

/**
 * An instruction generated by the assembler. Contains the Operation type,
 * a callback to emit the instruction to a code buffer, and all the parameters
 * accepted by the callback.
 *
 * Callback arguments can be inspected and modified to facilitate intermediate
 * code generation/optimization passes.
 */
class instruction_stream_entry {
public:
    using asm_param = std::variant<bool, uint8_t, uint16_t, uint32_t, int8_t, int16_t, int32_t, BO, SPR>;

    template <typename... Ts>
    instruction_stream_entry(Operation op_, std::function<status_code(assembler*, asm_param*)> emit_, Ts&&... parameters_)
            : op(op_), emit(std::move(emit_)), parameters({std::forward<Ts>(parameters_)...}) {
        static_assert(sizeof...(parameters_) <= 6, "Too many insn parameters provided!");
    }

    instruction_stream_entry(instruction_stream_entry&& other)
        : aux(std::move(other.aux)), op(other.op),
          emit(std::move(other.emit)), parameters(std::move(other.parameters)) {}
    ~instruction_stream_entry();
    instruction_stream_entry(const instruction_stream_entry& other) = delete;
    instruction_stream_entry &operator=(const instruction_stream_entry &other) = delete;
    instruction_stream_entry &operator=(instruction_stream_entry &&other) = delete;

    /**
     * Emit the instruction using the provided assembler.
     */
    status_code operator()(assembler *a) {
        return emit(a, &parameters[0]);
    }

    /**
     * Set the auxiliary data value
     */
    template <typename... Ts>
    void set_aux(Ts&&... args) {
        aux = std::make_unique<instruction_aux>(std::forward<Ts>(args)...);
    }

    //
    // Accessors
    //

    /**
     * Returns a reference to the stored parameter for assembler function `F` at index `i`.
     * For example, if `my_insn` is an instruction of type Operation::B,
     *   my_insn.parameter<0>(&assembler::b_internal)
     * will return an int32_t&, since the first parameter of assembler::b_internal is an int32_t.
     *
     * You should probably use the `insn_arg` helper template instead, which accepts
     * a constexpr `Operation` value and selects the correct method signature accordingly.
     */
    template<size_t i, typename... F>
    auto &parameter(F&&...) {
        using ArgT = typename magic::function_traits<F...>::template ArgsT<i>;
        return std::get<ArgT>(parameters[i]);
    }

    Operation operation() const { return op; }

    std::unique_ptr<instruction_aux> aux;
private:
    Operation op;
    // This will call our write32() function to write the instruction to `out_buf`.
    std::function<status_code(assembler*, asm_param*)> emit;
    std::array<asm_param, 6> parameters;
};

struct instruction_stream_traits {
    using AssemblerT = assembler;
    using InsnT = instruction_stream_entry;

    static size_t calculate_code_size([[maybe_unused]] const instruction_stream_entry *code_buf, size_t count) {
        // Ignoring ISA 3.1 8-byte instructions which we don't emit, the size of
        // the emitted code is simply the number of entries * 4.
        return count * INSN_SIZE;
    }
};

// instruction_stream for the ppc64le backend
class instruction_stream final : public retrec::instruction_stream<instruction_stream_traits> {
    using retrec::instruction_stream<instruction_stream_traits>::instruction_stream;
};

/**
 * The assembler itself. Contains functions for easily adding instructions to an instruction_stream.
 */
class assembler {
    instruction_stream *stream { nullptr };

    status_code write32(uint32_t x);

    status_code b_form(uint8_t po, uint8_t bo, uint8_t bi, uint16_t bd, uint8_t aa, uint8_t lk);
    status_code d_form(uint8_t po, uint8_t rt, uint8_t ra, uint16_t i);
    status_code ds_form(uint8_t po, uint8_t rs, uint8_t ra, uint16_t ds, uint8_t xo);
    status_code dx_form(uint8_t po, uint8_t rt, int16_t d, uint8_t xo);
    status_code i_form(uint8_t po, int32_t li, uint8_t aa, uint8_t lk);
    status_code m_form(uint8_t po, uint8_t rs, uint8_t ra, uint8_t sh, uint8_t mb, uint8_t me, uint8_t rc);
    status_code md_form(uint8_t po, uint8_t rs, uint8_t ra, uint8_t sh, uint8_t mb, uint8_t xo, uint8_t rc);
    status_code mds_form(uint8_t po, uint8_t rs, uint8_t ra, uint8_t rb, uint8_t mb, uint8_t xo, uint8_t rc);
    status_code sc_form(uint8_t po, uint8_t lev);
    status_code x_form(uint8_t po, uint8_t rs, uint8_t ra, uint8_t rb, uint16_t xo, uint8_t rc);
    status_code xfx_form(uint8_t po, uint8_t rt, uint16_t spr, uint16_t xo);
    status_code xl_form(uint8_t po, uint8_t bt, uint8_t ba, uint8_t bb, uint16_t xo, uint8_t lk);
    status_code xo_form(uint8_t po, uint8_t rt, uint8_t ra, uint8_t rb, uint8_t oe, uint16_t xo, uint8_t rc);

public:
    // Helper for checking if values fit within a provided mask
    template <typename ValT, typename MaskT>
    static std::enable_if_t<std::is_integral_v<ValT> && std::is_integral_v<MaskT>, bool>
    fits_in_mask(ValT val, MaskT mask) {
        if constexpr (std::is_unsigned_v<ValT>) {
            return (val & mask) == val;
        } else {
            // For signed numbers, we check if the value violates the mask differently when the value is negative
            if (val < 0)
                return static_cast<ValT>((val | ~(mask))) == val;
            else
                return static_cast<ValT>((val & mask)) == val;
        }
    }

    // Helper for asserting that values fit within a provided mask
    template <typename ValT, typename MaskT>
    static std::enable_if_t<std::is_integral_v<ValT> && std::is_integral_v<MaskT>, void>
    check_mask(ValT val, MaskT mask) {
        assert(fits_in_mask(val, mask));
    }

    assembler() {}
    ~assembler();

    void set_stream(instruction_stream *stream_) { stream = stream_; }
    auto &get_stream() { return stream; }

    //
    // Book I
    //

    // 2.4 Branch Instructions
    static constexpr uint8_t CR_LT = 0;
    static constexpr uint8_t CR_GT = 1;
    static constexpr uint8_t CR_EQ = 2;
    static constexpr uint8_t CR_SO = 3;

    /**
     * Helper macro to create an instruction_stream entry that emits an instruction.
     *
     * Upon invocation of an assembler instruction method (e.g. addi), we need to create an
     * instruction object which stores the Operation type, the parameters passed to the method,
     * and a callback for actually emitting the instruction to a code buffer. This macro assists in
     * creating the instruction and adding it to the instruction_stream. It accepts an Operation type,
     * a callback lambda, and a list of parameters to store.
     *
     * The callback lambda is the most interesting part, as the macro will automatically unpack
     * all saved function arguments before calling it. This is done using the FOR_EACH macro
     * (see util/magic.h) to declare a new variable for each parameter in the lambda's parent
     * scope. Each new variable is a type-correct reference to an entry in the instruction object's
     * parameter pack with the same name as the original parameter. The end result is that from
     * the lambda's perspective, it is as if the original parameters were captured directly.
     *
     * The benefit of doing this instead of directly capturing the parameters is that it allows
     * us to inspect and modify the parameters in intermediate passes that occur after the
     * instruction is created but before it is actually emitted. One obvious use case for this
     * is performing relocations by scanning through the instruction stream and modifying
     * instructions as required.
     */
#define EMIT_INSN(op, implementation, ...) \
        stream->emplace_back(op, [](auto *self, [[maybe_unused]] auto *params) -> status_code { \
            UNPACK_ARGS(__VA_ARGS__) \
            return implementation(); \
        }, ##__VA_ARGS__);
#define UNPACK(x) decltype(x) x = *(decltype(x)*)(&params[n++]);
#define UNPACK_ARGS(...) [[maybe_unused]] uint8_t n = 0; FOR_EACH(UNPACK, ##__VA_ARGS__)

    void b_internal(int32_t target, bool aa, bool lk) {
        ASM_LOG("Emitting b%s%s 0x%x\n", lk?"l":"", aa?"a":"", target);

        EMIT_INSN(Operation::B, [=] {
            assert((target & 0b11) == 0);
            return self->i_form(18, target>>2, aa, lk);
        }, target, aa, lk);
    }
    void b(int32_t li)   { b_internal(li, 0, 0); }
    void ba(int32_t li)  { b_internal(li, 1, 0); }
    void bl(int32_t li)  { b_internal(li, 0, 1); }
    void bla(int32_t li) { b_internal(li, 1, 1); }

    void bc_internal(BO bo, uint8_t bi, uint16_t target, bool aa, bool lk) {
        ASM_LOG("Emitting bc%s%s %u %u 0x%x\n", lk?"l":"", aa?"a":"", (uint8_t)bo, bi, target);

        EMIT_INSN(Operation::BC, [=] {
            assert((target & 0b11U) == 0);
            return self->b_form(16, (uint8_t)bo, bi, target>>2, aa, lk);
        }, bo, bi, target, aa, lk);
    }
    void bc(BO bo, uint8_t bi, uint16_t target)   { bc_internal(bo, bi, target, 0, 0); }
    void bca(BO bo, uint8_t bi, uint16_t target)  { bc_internal(bo, bi, target, 1, 0); }
    void bcl(BO bo, uint8_t bi, uint16_t target)  { bc_internal(bo, bi, target, 0, 1); }
    void bcla(BO bo, uint8_t bi, uint16_t target) { bc_internal(bo, bi, target, 1, 1); }

    void bcctr_internal(BO bo, uint8_t bi, uint8_t bh, bool lk) {
        ASM_LOG("Emitting bcctr%s %d %d %d\n", lk?"l":"", (uint8_t)bo, bi, bh);
        EMIT_INSN(Operation::BCCTR, [=] {
            return self->xl_form(19, (uint8_t)bo, bi, bh, 528, lk);
        }, bo, bi, bh, lk);
    }
    void bcctr(BO bo, uint8_t bi, uint8_t bh)  { bcctr_internal(bo, bi, bh, 0); }
    void bcctrl(BO bo, uint8_t bi, uint8_t bh) { bcctr_internal(bo, bi, bh, 1); }
    void bctr()  { bcctr_internal(BO::ALWAYS, 0, 0, 0); }
    void bctrl() { bcctr_internal(BO::ALWAYS, 0, 0, 1); }

    // 2.5.1 Condition Register Logical Instructions
    void crand(uint8_t bt, uint8_t ba, uint8_t bb) {
        ASM_LOG("Emitting crand %u, %u, %u\n", bt, ba, bb);
        EMIT_INSN(Operation::CRAND, [=] {
            return self->xl_form(19, bt, ba, bb, 257, 0);
        }, bt, ba, bb);
    }

    void crnand(uint8_t bt, uint8_t ba, uint8_t bb) {
        ASM_LOG("Emitting crnand %u, %u, %u\n", bt, ba, bb);
        EMIT_INSN(Operation::CRNAND, [=] {
            return self->xl_form(19, bt, ba, bb, 255, 0);
        }, bt, ba, bb);
    }

    void cror(uint8_t bt, uint8_t ba, uint8_t bb) {
        ASM_LOG("Emitting cror %u, %u, %u\n", bt, ba, bb);
        EMIT_INSN(Operation::CROR, [=] {
            return self->xl_form(19, bt, ba, bb, 449, 0);
        }, bt, ba, bb);
    }
    void crmove(uint8_t bx, uint8_t by) { cror(bx, by, by); }

    void crxor(uint8_t bt, uint8_t ba, uint8_t bb) {
        ASM_LOG("Emitting crxor %u, %u, %u\n", bt, ba, bb);
        EMIT_INSN(Operation::CRXOR, [=] {
            return self->xl_form(19, bt, ba, bb, 193, 0);
        }, bt, ba, bb);
    }
    void crclr(uint8_t bx) { crxor(bx, bx, bx); }

    void crnor(uint8_t bt, uint8_t ba, uint8_t bb) {
        ASM_LOG("Emitting crnor %u, %u, %u\n", bt, ba, bb);
        EMIT_INSN(Operation::CRNOR, [=] {
            return self->xl_form(19, bt, ba, bb, 33, 0);
        }, bt, ba, bb);

    }
    void crnot(uint8_t bx, uint8_t by) { crnor(bx, by, by); }

    void creqv(uint8_t bt, uint8_t ba, uint8_t bb) {
        ASM_LOG("Emitting creqv %u, %u, %u\n", bt, ba, bb);
        EMIT_INSN(Operation::CREQV, [=] {
            return self->xl_form(19, bt, ba, bb, 289, 0);
        }, bt, ba, bb);
    }
    void crset(uint8_t bx) { creqv(bx, bx, bx); }

    void crandc(uint8_t bt, uint8_t ba, uint8_t bb) {
        ASM_LOG("Emitting crandc %u, %u, %u\n", bt, ba, bb);
        EMIT_INSN(Operation::CRANDC, [=] {
            return self->xl_form(19, bt, ba, bb, 129, 0);
        }, bt, ba, bb);
    }

    void crorc(uint8_t bt, uint8_t ba, uint8_t bb) {
        ASM_LOG("Emitting crorc %u, %u, %u\n", bt, ba, bb);
        EMIT_INSN(Operation::CRORC, [=] {
            return self->xl_form(19, bt, ba, bb, 417, 0);
        }, bt, ba, bb);
    }

    void mcrf(uint8_t bf, uint8_t bfa) {
        ASM_LOG("Emitting mcrf cr%u, %u\n", bf, bfa);
        EMIT_INSN(Operation::MCRF, [=] {
            check_mask(bf, 0b111U);
            check_mask(bfa, 0b111U);
            return self->xl_form(19, (uint8_t)(bf << 2), (uint8_t)(bfa << 2), 0, 0, 0);
        }, bf, bfa);
    }

    // 3.3.2 Fixed-Point Load Instructions
    void lbz(uint8_t rt, uint8_t ra, int16_t d) {
        ASM_LOG("Emitting lbz r%u, 0x%x(r%u)\n", rt, d, ra);
        EMIT_INSN(Operation::LBZ, [=] {
            return self->d_form(34, rt, ra, d);
        }, rt, ra, d);
    }

    void lbzx(uint8_t rt, uint8_t ra, uint8_t rb) {
        ASM_LOG("Emitting lbzx r%u, r%u, r%u\n", rt, ra, rb);
        EMIT_INSN(Operation::LBZX, [=] {
            return self->x_form(31, rt, ra, rb, 87, 0);
        }, rt, ra, rb);
    }

    void lhz(uint8_t rt, uint8_t ra, int16_t d) {
        ASM_LOG("Emitting lhz r%u, 0x%x(r%u)\n", rt, d, ra);
        EMIT_INSN(Operation::LHZ, [=] {
            return self->d_form(40, rt, ra, d);
        }, rt, ra, d);
    }

    void lhzx(uint8_t rt, uint8_t ra, uint8_t rb) {
        ASM_LOG("Emitting lbhx r%u, r%u, r%u\n", rt, ra, rb);
        EMIT_INSN(Operation::LHZX, [=] {
            return self->x_form(31, rt, ra, rb, 279, 0);
        }, rt, ra, rb);
    }

    void lwz(uint8_t rt, uint8_t ra, int16_t d) {
        ASM_LOG("Emitting lwz r%u, 0x%x(r%u)\n", rt, d, ra);
        EMIT_INSN(Operation::LWZ, [=] {
            return self->d_form(32, rt, ra, d);
        }, rt, ra, d);
    }

    void lwzx(uint8_t rt, uint8_t ra, uint8_t rb) {
        ASM_LOG("Emitting lwhx r%u, r%u, r%u\n", rt, ra, rb);
        EMIT_INSN(Operation::LWZX, [=] {
            return self->x_form(31, rt, ra, rb, 23, 0);
        }, rt, ra, rb);
    }

    void ld(uint8_t rt, uint8_t ra, int16_t ds) {
        ASM_LOG("Emitting ld r%u, 0x%x(r%u)\n", rt, ds, ra);
        EMIT_INSN(Operation::LD, [=] {
            check_mask(ds, 0xFFFC);
            return self->ds_form(58, rt, ra, ds, 0);
        }, rt, ra, ds);
    }

    void ldx(uint8_t rt, uint8_t ra, uint8_t rb) {
        ASM_LOG("Emitting ldx r%u, r%u, r%u\n", rt, ra, rb);
        EMIT_INSN(Operation::LDX, [=] {
            return self->x_form(31, rt, ra, rb, 21, 0);
        }, rt, ra, rb);
    }

    // 3.3.3 Fixed-Point Store Instructions
    void stb(uint8_t rs, uint8_t ra, int16_t d) {
        ASM_LOG("Emitting stb r%u, 0x%x(r%u)\n", rs, d, ra);
        EMIT_INSN(Operation::STB, [=] {
            return self->d_form(38, rs, ra, d);
        }, rs, ra, d);
    }

    void stbx(uint8_t rs, uint8_t ra, uint8_t rb) {
        ASM_LOG("Emitting stbx r%u, r%u, r%u\n", rs, ra, rb);
        EMIT_INSN(Operation::STBX, [=] {
            return self->x_form(31, rs, ra, rb, 215, 0);
        }, rs, ra, rb);
    }

    void sth(uint8_t rs, uint8_t ra, int16_t d) {
        ASM_LOG("Emitting sth r%u, 0x%x(r%u)\n", rs, d, ra);
        EMIT_INSN(Operation::STH, [=] {
            return self->d_form(44, rs, ra, d);
        }, rs, ra, d);
    }

    void sthx(uint8_t rs, uint8_t ra, uint8_t rb) {
        ASM_LOG("Emitting sthx r%u, r%u, r%u\n", rs, ra, rb);
        EMIT_INSN(Operation::STHX, [=] {
            return self->x_form(31, rs, ra, rb, 407, 0);
        }, rs, ra, rb);
    }

    void stw(uint8_t rs, uint8_t ra, int16_t d) {
        ASM_LOG("Emitting stw r%u, 0x%x(r%u)\n", rs, d, ra);
        EMIT_INSN(Operation::STW, [=] {
            return self->d_form(36, rs, ra, d);
        }, rs, ra, d);
    }

    void stwx(uint8_t rs, uint8_t ra, uint8_t rb) {
        ASM_LOG("Emitting stwx r%u, r%u, r%u\n", rs, ra, rb);
        EMIT_INSN(Operation::STWX, [=] {
            return self->x_form(31, rs, ra, rb, 151, 0);
        }, rs, ra, rb);
    }

    void std(uint8_t rs, uint8_t ra, int16_t ds) {
        ASM_LOG("Emitting std r%u, 0x%x(r%u)\n", rs, ds, ra);
        EMIT_INSN(Operation::STD, [=] {
            check_mask(ds, 0xFFFC);
            return self->ds_form(62, rs, ra, ds, 0);
        }, rs, ra, ds);
    }

    void stdx(uint8_t rs, uint8_t ra, uint8_t rb) {
        ASM_LOG("Emitting stdx r%u, r%u, r%u\n", rs, ra, rb);
        EMIT_INSN(Operation::STDX, [=] {
            return self->x_form(31, rs, ra, rb, 149, 0);
        }, rs, ra, rb);
    }

    // 3.3.9 Fixed-Point Arithmetic Instructions
    void addi(uint8_t rt, uint8_t ra, int16_t si) {
        ASM_LOG("Emitting addi r%u, r%u, 0x%x\n", rt, ra, si);
        EMIT_INSN(Operation::ADDI, [=] {
            return self->d_form(14, rt, ra, (uint16_t)si);
        }, rt, ra, si);
    };

    void addis(uint8_t rt, uint8_t ra, int16_t si) {
        ASM_LOG("Emitting addis r%u, r%u, 0x%x\n", rt, ra, si);
        EMIT_INSN(Operation::ADDIS, [=] {
            return self->d_form(15, rt, ra, (uint16_t)si);
        }, rt, ra, si);
    };

    void addpcis(uint8_t rt, int16_t d) {
        ASM_LOG("Emitting addpcis r%u, 0x%x\n", rt, d);
        EMIT_INSN(Operation::ADDPCIS, [=] {
            return self->dx_form(19, rt, d, 2);
        }, rt, d);
    }
    void lnia(uint8_t rt) { addpcis(rt, 0); }

    void add_internal(uint8_t rt, uint8_t ra, uint8_t rb, bool modify_ov, bool modify_cr) {
        ASM_LOG("Emitting add%s%s r%u, r%u, r%u\n", modify_ov?"o":"", modify_cr?".":"", rt, ra, rb);
        EMIT_INSN(Operation::ADD, [=] {
            return self->xo_form(31, rt, ra, rb, modify_ov, 266, modify_cr);
        }, rt, ra, rb, modify_ov, modify_cr);
    }
    void add(uint8_t rt, uint8_t ra, uint8_t rb)   { add_internal(rt, ra, rb, 0, 0); }
    void add_(uint8_t rt, uint8_t ra, uint8_t rb)  { add_internal(rt, ra, rb, 0, 1); }
    void addo(uint8_t rt, uint8_t ra, uint8_t rb)  { add_internal(rt, ra, rb, 1, 0); }
    void addo_(uint8_t rt, uint8_t ra, uint8_t rb) { add_internal(rt, ra, rb, 1, 1); }

    void sub_internal(uint8_t rt, uint8_t rb, uint8_t ra, bool modify_ov, bool modify_cr) {
        ASM_LOG("Emitting sub%s%s r%u, r%u, r%u\n", modify_ov?"o":"", modify_cr?".":"", rt, rb, ra);
        EMIT_INSN(Operation::SUB, [=] {
            return self->xo_form(31, rt, ra, rb, modify_ov, 40, modify_cr);
        }, rt, ra, rb, modify_ov, modify_cr);
    }
    void sub(uint8_t rt, uint8_t rb, uint8_t ra)   { sub_internal(rt, rb, ra, 0, 0); }
    void sub_(uint8_t rt, uint8_t rb, uint8_t ra)  { sub_internal(rt, rb, ra, 0, 1); }
    void subo(uint8_t rt, uint8_t rb, uint8_t ra)  { sub_internal(rt, rb, ra, 1, 0); }
    void subo_(uint8_t rt, uint8_t rb, uint8_t ra) { sub_internal(rt, rb, ra, 1, 1); }

    void subc_internal(uint8_t rt, uint8_t rb, uint8_t ra, bool modify_ov, bool modify_cr) {
        ASM_LOG("Emitting subc%s%s r%u, r%u, r%u\n", modify_ov?"o":"", modify_cr?".":"", rt, rb, ra);
        EMIT_INSN(Operation::SUBC, [=] {
            return self->xo_form(31, rt, ra, rb, modify_ov, 8, modify_cr);
        }, rt, ra, rb, modify_ov, modify_cr);
    }
    void subc(uint8_t rt, uint8_t rb, uint8_t ra)   { subc_internal(rt, rb, ra, 0, 0); }
    void subc_(uint8_t rt, uint8_t rb, uint8_t ra)  { subc_internal(rt, rb, ra, 0, 1); }
    void subco(uint8_t rt, uint8_t rb, uint8_t ra)  { subc_internal(rt, rb, ra, 1, 0); }
    void subco_(uint8_t rt, uint8_t rb, uint8_t ra) { subc_internal(rt, rb, ra, 1, 1); }

    void sube_internal(uint8_t rt, uint8_t rb, uint8_t ra, bool modify_ov, bool modify_cr) {
        ASM_LOG("Emitting sube%s%s r%u, r%u, r%u\n", modify_ov?"o":"", modify_cr?".":"", rt, rb, ra);
        EMIT_INSN(Operation::SUBE, [=] {
            return self->xo_form(31, rt, ra, rb, modify_ov, 136, modify_cr);
        }, rt, ra, rb, modify_ov, modify_cr);
    }
    void sube(uint8_t rt, uint8_t rb, uint8_t ra)   { sube_internal(rt, rb, ra, 0, 0); }
    void sube_(uint8_t rt, uint8_t rb, uint8_t ra)  { sube_internal(rt, rb, ra, 0, 1); }
    void subeo(uint8_t rt, uint8_t rb, uint8_t ra)  { sube_internal(rt, rb, ra, 1, 0); }
    void subeo_(uint8_t rt, uint8_t rb, uint8_t ra) { sube_internal(rt, rb, ra, 1, 1); }

    void neg_internal(uint8_t rt, uint8_t ra, bool modify_ov, bool modify_cr) {
        ASM_LOG("Emitting neg%s%s r%u, r%u\n", modify_ov?"o":"", modify_cr?".":"", rt, ra);
        EMIT_INSN(Operation::NEG, [=] {
            return self->xo_form(31, rt, ra, 0, modify_ov, 104, modify_cr);
        }, rt, ra, modify_ov, modify_cr);
    }
    void neg(uint8_t rt, uint8_t rb)   { neg_internal(rt, rb, 0, 0); }
    void neg_(uint8_t rt, uint8_t rb)  { neg_internal(rt, rb, 0, 1); }
    void nego(uint8_t rt, uint8_t rb)  { neg_internal(rt, rb, 1, 0); }
    void nego_(uint8_t rt, uint8_t rb) { neg_internal(rt, rb, 1, 1); }

    // 3.3.10 Fixed-Point Compare Instructions
    void cmpi(uint8_t bf, bool l, uint8_t ra, int16_t si) {
        ASM_LOG("Emitting cmpi %u, %u, r%u, %d\n", bf, l, ra, si);
        EMIT_INSN(Operation::CMPI, [=] {
            check_mask(bf, 0b111U);
            uint8_t rt = (uint8_t)((bf << (uint8_t)2U) | (l & (uint8_t)1U));
            return self->d_form(11, rt, ra, si);
        }, bf, l, ra, si);
    }
    void cmpdi(uint8_t bf, uint8_t ra, uint16_t si) { cmpi(bf, true, ra, si); }
    void cmpwi(uint8_t bf, uint8_t ra, uint16_t si) { cmpi(bf, false, ra, si); }

    void cmp(uint8_t bf, bool l, uint8_t ra, uint8_t rb) {
        ASM_LOG("Emitting cmp %u, %u, r%u, r%u\n", bf, l, ra, rb);
        EMIT_INSN(Operation::CMP, [=] {
            check_mask(bf, 0b111U);
            uint8_t rs = (uint8_t)((bf << (uint8_t)2U) | (l & (uint8_t)1U));
            return self->x_form(31, rs, ra, rb, 0, 0);
        }, bf, l, ra, rb);
    }
    void cmpd(uint8_t bf, uint8_t ra, uint8_t rb) { cmp(bf, true, ra, rb); }
    void cmpw(uint8_t bf, uint8_t ra, uint8_t rb) { cmp(bf, false, ra, rb); }

    void cmpli(uint8_t bf, uint8_t l, uint8_t ra, uint16_t ui) {
        ASM_LOG("Emitting cmpli %u, %u, r%u, r%u\n", bf, l, ra, ui);
        EMIT_INSN(Operation::CMPLI, [=] {
            check_mask(l, 1U);
            check_mask(bf, 0b111U);
            uint8_t rs = (uint8_t) (bf << (uint8_t)2U) | (l & (uint8_t)1U);
            return self->d_form(10, rs, ra, ui);
        }, bf, l, ra, ui);
    }
    void cmpldi(uint8_t bf, uint8_t ra, uint16_t ui) { cmpli(bf, 1, ra, ui); }
    void cmplwi(uint8_t bf, uint8_t ra, uint16_t ui) { cmpli(bf, 0, ra, ui); }

    void cmpl(uint8_t bf, uint8_t l, uint8_t ra, uint8_t rb) {
        ASM_LOG("Emitting cmpl %u, %u, r%u, r%u\n", bf, l, ra, rb);
        EMIT_INSN(Operation::CMPL, [=] {
            check_mask(l, 1U);
            check_mask(bf, 0b111U);
            uint8_t rs = (uint8_t) (bf << (uint8_t)2U) | (l & (uint8_t)1U);
            return self->x_form(31, rs, ra, rb, 32, 0);
        }, bf, l, ra, rb);
    }

    // 3.3.13 Fixed-Point Logical Instructions
    void andi_(uint8_t ra, uint8_t rs, uint16_t ui) {
        ASM_LOG("Emitting andi. r%u, r%u, 0x%x\n", ra, rs, ui);
        EMIT_INSN(Operation::ANDI_, [=] {
            return self->d_form(28, rs, ra, ui);
        }, ra, rs, ui);
    }

    void ori(uint8_t ra, uint8_t rs, uint16_t ui) {
        ASM_LOG("Emitting ori r%u, r%u, 0x%x\n", ra, rs, ui);
        EMIT_INSN(Operation::ORI, [=] {
            return self->d_form(24, rs, ra, ui);
        }, ra, rs, ui);
    }
    void nop() { ori(0, 0, 0); }

    void oris(uint8_t ra, uint8_t rs, uint16_t ui) {
        ASM_LOG("Emitting oris r%u, r%u, 0x%x\n", ra, rs, ui);
        EMIT_INSN(Operation::ORIS, [=] {
            return self->d_form(25, rs, ra, ui);
        }, ra, rs, ui);
    }

    void _and(uint8_t ra, uint8_t rs, uint8_t rb) {
        ASM_LOG("Emitting and r%u, r%u, r%u\n", ra, rs, rb);
        EMIT_INSN(Operation::AND, [=] {
            return self->x_form(31, rs, ra, rb, 28, 0);
        }, ra, rs, rb);
    }
    void _and_(uint8_t ra, uint8_t rs, uint8_t rb) {
        ASM_LOG("Emitting and. r%u, r%u, r%u\n", ra, rs, rb);
        EMIT_INSN(Operation::AND, [=] {
            return self->x_form(31, rs, ra, rb, 28, 1);
        }, ra, rs, rb);
    }

    void _xor(uint8_t ra, uint8_t rs, uint8_t rb) {
        ASM_LOG("Emitting xor r%u, r%u, r%u\n", ra, rs, rb);
        EMIT_INSN(Operation::XOR, [=] {
            return self->x_form(31, rs, ra, rb, 316, 0);
        }, ra, rs, rb);
    }
    void _xor_(uint8_t ra, uint8_t rs, uint8_t rb) {
        ASM_LOG("Emitting xor. r%u, r%u, r%u\n", ra, rs, rb);
        EMIT_INSN(Operation::XOR, [=] {
            return self->x_form(31, rs, ra, rb, 316, 1);
        }, ra, rs, rb);
    }

    void _or(uint8_t ra, uint8_t rs, uint8_t rb) {
        ASM_LOG("Emitting or r%u, r%u, r%u\n", ra, rs, rb);
        EMIT_INSN(Operation::OR, [=] {
            return self->x_form(31, rs, ra, rb, 444, 0);
        }, ra, rs, rb);
    }
    void _or_(uint8_t ra, uint8_t rs, uint8_t rb) {
        ASM_LOG("Emitting or. r%u, r%u, r%u\n", ra, rs, rb);
        EMIT_INSN(Operation::OR, [=] {
            return self->x_form(31, rs, ra, rb, 444, 1);
        }, ra, rs, rb);
    }
    void mr(uint8_t rx, uint8_t ry) { _or(rx, ry, ry); }

    void eqv(uint8_t ra, uint8_t rs, uint8_t rb) {
        ASM_LOG("Emitting eqv r%u, r%u, r%u\n", ra, rs, rb);
        EMIT_INSN(Operation::EQV, [=] {
            return self->x_form(31, rs, ra, rb, 284, 0);
        }, ra, rs, rb);
    }
    void eqv_(uint8_t ra, uint8_t rs, uint8_t rb) {
        ASM_LOG("Emitting eqv. r%u, r%u, r%u\n", ra, rs, rb);
        EMIT_INSN(Operation::EQV, [=] {
            return self->x_form(31, rs, ra, rb, 284, 1);
        }, ra, rs, rb);
    }

    void extsb(uint8_t ra, uint8_t rs, bool modify_cr = false) {
        ASM_LOG("Emitting extsb%s r%u, r%u\n", modify_cr?".":"", ra, rs);
        EMIT_INSN(Operation::EXTSB, [=] {
            return self->x_form(31, rs, ra, 0, 954, modify_cr);
        }, ra, rs, modify_cr);
    }

    void extsh(uint8_t ra, uint8_t rs, bool modify_cr = false) {
        ASM_LOG("Emitting extsh%s r%u, r%u\n", modify_cr?".":"", ra, rs);
        EMIT_INSN(Operation::EXTSH, [=] {
            return self->x_form(31, rs, ra, 0, 922, modify_cr);
        }, ra, rs, modify_cr);
    }

    // 3.3.14 Fixed-Point Rotate and Shift Instruction
    void rlwinm(uint8_t ra, uint8_t rs, uint8_t sh, uint8_t mb, uint8_t me, bool modify_cr = false) {
        ASM_LOG("Emitting rlwinm%s r%u, r%u, %u, %u, %u\n", modify_cr?".":"", ra, rs, sh, mb, me);
        EMIT_INSN(Operation::RLWINM, [=] {
            return self->m_form(21, rs, ra, sh, mb, me, modify_cr);
        }, ra, rs, sh, mb, me, modify_cr);
    }

    void rlwimi(uint8_t ra, uint8_t rs, uint8_t sh, uint8_t mb, uint8_t me, bool modify_cr = false) {
        ASM_LOG("Emitting rlwimi%s r%u, r%u, %u, %u, %u\n", modify_cr?".":"", ra, rs, sh, mb, me);
        EMIT_INSN(Operation::RLWIMI, [=] {
            return self->m_form(20, rs, ra, sh, mb, me, modify_cr);
        }, ra, rs, sh, mb, me, modify_cr);
    }

    void rldicl(uint8_t ra, uint8_t rs, uint8_t sh, uint8_t me, bool modify_cr) {
        ASM_LOG("Emitting rldicl%s r%u, r%u, %u, %u\n", modify_cr?".":"", ra, rs, sh, me);
        EMIT_INSN(Operation::RLDICL, [=] {
            return self->md_form(30, rs, ra, sh, me, 0, modify_cr);
        }, ra, rs, sh, me, modify_cr);
    }
    void srdi(uint8_t rx, uint8_t ry, uint8_t n, bool modify_cr) {
        check_mask(n, 0b11111U);
        rldicl(rx, ry, 64-n, n, modify_cr);
    }

    void rldicr(uint8_t ra, uint8_t rs, uint8_t sh, uint8_t me, bool modify_cr) {
        ASM_LOG("Emitting rldicr%s r%u, r%u, %u, %u\n", modify_cr?".":"", ra, rs, sh, me);
        EMIT_INSN(Operation::RLDICR, [=] {
            return self->md_form(30, rs, ra, sh, me, 1, modify_cr);
        }, ra, rs, sh, me, modify_cr);
    }
    void sldi(uint8_t rx, uint8_t ry, uint8_t n, bool modify_cr = false) {
        check_mask(n, 0b11111U);
        rldicr(rx, ry, n, 63-n, modify_cr);
    }

    void rldcl(uint8_t ra, uint8_t rs, uint8_t rb, uint8_t mb, bool modify_cr) {
        ASM_LOG("Emitting rldcl%s r%u, r%u, r%u, %u\n", modify_cr?".":"", ra, rs, rb, mb);
        EMIT_INSN(Operation::RLDCL, [=] {
            return self->mds_form(30, rs, ra, rb, mb, 8, modify_cr);
        }, ra, rs, rb, mb, modify_cr);
    }

    void rldimi(uint8_t ra, uint8_t rs, uint8_t sh, uint8_t mb, bool modify_cr) {
        ASM_LOG("Emitting rldimi%s r%u, r%u, %u, %u\n", modify_cr?".":"", ra, rs, sh, mb);
        EMIT_INSN(Operation::RLDIMI, [=] {
            return self->md_form(30, rs, ra, sh, mb, 3, modify_cr);
        }, ra, rs, sh, mb, modify_cr);
    }
    void insrdi(uint8_t rt, uint8_t ra, uint8_t n, uint8_t b, bool modify_cr) { rldimi(rt, ra, (uint8_t)(64-(b+n)), b, modify_cr); }

    // 3.3.17 Move To/From System Register Instructions
    void mtspr(SPR spr, uint8_t rs) {
        ASM_LOG("Emitting mtspr r%u, %u\n", rs, (uint16_t)spr);
        EMIT_INSN(Operation::MTSPR, [=] {
            uint16_t n = (uint16_t) (((uint16_t)spr & 0b11111U) << 5) | (((uint16_t)spr >> 5) & 0b11111U);
            return self->xfx_form(31, rs, n, 467);
        }, spr, rs);
    }

    void mfspr(uint8_t rt, SPR spr) {
        ASM_LOG("Emitting mfspr r%u, %u\n", rt, (uint16_t)spr);
        EMIT_INSN(Operation::MFSPR, [=] {
            uint16_t n = (uint16_t) (((uint16_t)spr & 0b11111U) << 5) | (((uint16_t)spr >> 5) & 0b11111U);
            return self->xfx_form(31, rt, n, 339);
        }, rt, spr);
    }

    void mcrxrx(uint8_t bf) {
        ASM_LOG("Emitting mcrxrx %u\n", bf);
        EMIT_INSN(Operation::MCRXRX, [=] {
            check_mask(bf, 0b111U);
            return self->x_form(31, (uint8_t)(bf << 2), 0, 0, 576, 0);
        }, bf);
    }

    void mtocrf(uint8_t fxm, uint8_t rs) {
        ASM_LOG("Emitting mtcrf 0x%x, r%u\n", fxm, rs);
        EMIT_INSN(Operation::MTOCRF, [=] {
            return self->xfx_form(31, rs, (uint16_t)(fxm << 1) | (1 << 8), 144);
        }, fxm, rs);
    }

    void mtcrf(uint8_t fxm, uint8_t rs) {
        ASM_LOG("Emitting mtcrf 0x%x, r%u\n", fxm, rs);
        EMIT_INSN(Operation::MTCRF, [=] {
            return self->xfx_form(31, rs, (uint16_t)(fxm << 1), 144);
        }, fxm, rs);
    }
    void mtcr(uint8_t rs) { mtcrf(0xFF, rs); }

    void mfocrf(uint8_t rt, uint8_t fxm) {
        ASM_LOG("Emitting mfocrf 0x%x, r%u,\n", rt, fxm);
        EMIT_INSN(Operation::MFOCRF, [=] {
            return self->xfx_form(31, rt, (uint16_t)((1 << 9) | (fxm << 1)), 19);
        }, rt, fxm);
    }

    void mfcr(uint8_t rt) {
        ASM_LOG("Emitting mfcr r%u\n", rt);
        EMIT_INSN(Operation::MFCR, [=] {
            return self->xfx_form(31, rt, 0, 19);
        }, rt);
    }

    //
    // Book III
    //

    // 3.3.1 System Linkage Instructions
    void sc() {
        ASM_LOG("Emitting sc\n");
        EMIT_INSN(Operation::SC, [=] {
            return self->sc_form(17, 0);
        });
    }

    // Guaranteed invalid instruction
    void invalid() {
        ASM_LOG("Emitting invalid instruction\n");
        EMIT_INSN(Operation::INVALID, [=] {
            return self->write32(0x00000000);
        });
    }

#undef EMIT_INSN
#undef UNPACK
#undef UNPACK_ARGS
};

/**
 * Define a lookup table that allows us to map constexpr Operation values to their
 * corresponding assembler:: method type. This can be used in conjunction with the
 * instruction_stream_entry class' parameter accessor to provide a type-safe way to access
 * parameters for a given Operation.
 */
#define ENUM_X(a, ignore) Operation::a,
#define TYPE_X(ignore, a) decltype(&a),
GEN_ENUM_TO_TYPE_LOOKUP(PPC64LE_ENUMERATE_OPERATIONS, operations, ENUM_X, TYPE_X, Operation)
#undef ENUM_X
#undef TYPE_X

/**
 * Obtain a reference to the `i`th argument of the instruction_stream_entry `insn` whose operation
 * type is `op`.
 */
template <size_t i, Operation op>
auto &insn_arg(instruction_stream_entry &insn) {
    return insn.parameter<i, operations_look_up_type<op>>(nullptr);
}

} // namespace ppc64le

} // namespace retrec
