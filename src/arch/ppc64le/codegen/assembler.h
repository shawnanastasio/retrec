#pragma once

#include <util.h>
#include <allocators.h>

#include <vector>
#include <cstddef>
#include <cstdint>

#define CHECK_MASK(val, mask) do { assert(((val) & (mask)) == (val)); } while(0)
#define CHECK_MASK_SIGNED(val, mask) \
    do { assert((static_cast<decltype(val)>((val) & (mask)) == (val)) || ((val) < 0 && static_cast<decltype(val)>((val) | ~(mask)) == (val)) ); } while(0)

// Comment out to disable log spam
#define ASM_LOG(...) log(LOGL_DEBUG, __VA_ARGS__)

#ifndef ASM_LOG
#define ASM_LOG(...)
#endif

namespace retrec {

namespace ppc64le {

class assembler {
    simple_region_writer &code_buf;

    // Only used for temporary assembler objects with different offsets
    bool temp;
    size_t old_pos;

    status_code write32(uint32_t val) { return code_buf.write32(val); }

    status_code b_form(uint8_t po, uint8_t bo, uint8_t bi, uint16_t bd, uint8_t aa, uint8_t lk);
    status_code d_form(uint8_t po, uint8_t rt, uint8_t ra, uint16_t i);
    status_code ds_form(uint8_t po, uint8_t rs, uint8_t ra, uint16_t ds, uint8_t xo);
    status_code dx_form(uint8_t po, uint8_t rt, int16_t d, uint8_t xo);
    status_code i_form(uint8_t po, int32_t li, uint8_t aa, uint8_t lk);
    status_code m_form(uint8_t po, uint8_t rs, uint8_t ra, uint8_t sh, uint8_t mb, uint8_t me, uint8_t rc);
    status_code md_form(uint8_t po, uint8_t rs, uint8_t ra, uint8_t sh, uint8_t mb, uint8_t xo, uint8_t rc);
    status_code sc_form(uint8_t po, uint8_t lev);
    status_code x_form(uint8_t po, uint8_t rs, uint8_t ra, uint8_t rb, uint16_t xo, uint8_t rc);
    status_code xfx_form(uint8_t po, uint8_t rt, uint16_t spr, uint16_t xo);
    status_code xl_form(uint8_t po, uint8_t bt, uint8_t ba, uint8_t bb, uint16_t xo, uint8_t lk);
    status_code xo_form(uint8_t po, uint8_t rt, uint8_t ra, uint8_t rb, uint8_t oe, uint16_t xo, uint8_t rc);

    assembler(assembler &other, size_t pos) : code_buf(other.code_buf), temp(true) {
        old_pos = code_buf.pos();
        code_buf.set_pos(pos);
    }

    // Extended mnemonics on p802
public:
    explicit assembler(simple_region_writer &code_buf_) : code_buf(code_buf_), temp(false) {}
    ~assembler();

    assembler create_temporary(size_t temp_pos) {
        return assembler(*this, temp_pos);
    }

    //
    // Book I
    //

    // 2.4 Branch Instructions
    enum class BO : uint8_t {
        ALWAYS = 0b10100,    // Branch unconditionally
        FIELD_CLR = 0b00100, // Branch if given CR field is clear (0)
        FIELD_SET = 0b01100  // Branch if given CR Field is set (1)
    };

    static constexpr uint8_t CR_LT = 0;
    static constexpr uint8_t CR_GT = 1;
    static constexpr uint8_t CR_EQ = 2;
    static constexpr uint8_t CR_SO = 3;

    status_code b_internal(int32_t li, uint8_t aa, uint8_t lk) {
        assert((li & 0b11) == 0);
        ASM_LOG("Emitting b%s%s 0x%llx to 0x%lx\n", lk?"l":"", aa?"a":"", li, code_buf.pos_addr());
        return i_form(18, li>>2, aa, lk);
    }
    status_code b(int32_t li)   { return b_internal(li, 0, 0); }
    status_code ba(int32_t li)  { return b_internal(li, 1, 0); }
    status_code bl(int32_t li)  { return b_internal(li, 0, 1); }
    status_code bla(int32_t li) { return b_internal(li, 1, 1); }

    status_code bc_internal(BO bo, uint8_t bi, uint16_t target, uint8_t aa, uint8_t lk) {
        assert((target & 0b11U) == 0);
        ASM_LOG("Emitting bc%s%s %u %u 0x%x to 0x%lx\n", lk?"l":"", aa?"a":"", (uint8_t)bo, bi, target,
            code_buf.pos_addr());
        return b_form(16, (uint8_t)bo, bi, target>>2, aa, lk);
    }
    status_code bc(BO bo, uint8_t bi, uint16_t target)   { return bc_internal(bo, bi, target, 0, 0); }
    status_code bca(BO bo, uint8_t bi, uint16_t target)  { return bc_internal(bo, bi, target, 1, 0); }
    status_code bcl(BO bo, uint8_t bi, uint16_t target)  { return bc_internal(bo, bi, target, 0, 1); }
    status_code bcla(BO bo, uint8_t bi, uint16_t target) { return bc_internal(bo, bi, target, 1, 1); }

    status_code bcctr_internal(BO bo, uint8_t bi, uint8_t bh, uint8_t lk) {
        ASM_LOG("Emitting bcctr%s %d %d %d to 0x%lx\n", lk?"l":"", (uint8_t)bo, bi, bh, code_buf.pos_addr());
        return xl_form(19, (uint8_t)bo, bi, bh, 528, lk);
    }
    status_code bcctr(BO bo, uint8_t bi, uint8_t bh)  { return bcctr_internal(bo, bi, bh, 0); }
    status_code bcctrl(BO bo, uint8_t bi, uint8_t bh) { return bcctr_internal(bo, bi, bh, 1); }
    status_code bctr()  { return bcctr_internal(BO::ALWAYS, 0, 0, 0); }
    status_code bctrl() { return bcctr_internal(BO::ALWAYS, 0, 0, 1); }

    // 2.5.1 Condition Register Logical Instructions
    status_code crand(uint8_t bt, uint8_t ba, uint8_t bb) {
        ASM_LOG("Emitting crand %u, %u, %u to 0x%lx\n", bt, ba, bb, code_buf.pos_addr());
        return xl_form(19, bt, ba, bb, 257, 0);
    }

    status_code crnand(uint8_t bt, uint8_t ba, uint8_t bb) {
        ASM_LOG("Emitting crnand %u, %u, %u to 0x%lx\n", bt, ba, bb, code_buf.pos_addr());
        return xl_form(19, bt, ba, bb, 225, 0);
    }

    status_code cror(uint8_t bt, uint8_t ba, uint8_t bb) {
        ASM_LOG("Emitting cror %u, %u, %u to 0x%lx\n", bt, ba, bb, code_buf.pos_addr());
        return xl_form(19, bt, ba, bb, 449, 0);
    }

    status_code crxor(uint8_t bt, uint8_t ba, uint8_t bb) {
        ASM_LOG("Emitting crxor %u, %u, %u to 0x%lx\n", bt, ba, bb, code_buf.pos_addr());
        return xl_form(19, bt, ba, bb, 193, 0);
    }
    status_code crclr(uint8_t bx) { return crxor(bx, bx, bx); }

    status_code crnor(uint8_t bt, uint8_t ba, uint8_t bb) {
        ASM_LOG("Emitting crnor %u, %u, %u to 0x%lx\n", bt, ba, bb, code_buf.pos_addr());
        return xl_form(19, bt, ba, bb, 33, 0);
    }

    status_code creqv(uint8_t bt, uint8_t ba, uint8_t bb) {
        ASM_LOG("Emitting creqv %u, %u, %u to 0x%lx\n", bt, ba, bb, code_buf.pos_addr());
        return xl_form(19, bt, ba, bb, 289, 0);
    }
    status_code crset(uint8_t bx) { return creqv(bx, bx, bx); }

    status_code crandc(uint8_t bt, uint8_t ba, uint8_t bb) {
        ASM_LOG("Emitting crandc %u, %u, %u to 0x%lx\n", bt, ba, bb, code_buf.pos_addr());
        return xl_form(19, bt, ba, bb, 129, 0);
    }

    status_code crorc(uint8_t bt, uint8_t ba, uint8_t bb) {
        ASM_LOG("Emitting crorc %u, %u, %u to 0x%lx\n", bt, ba, bb, code_buf.pos_addr());
        return xl_form(19, bt, ba, bb, 417, 0);
    }

    status_code mcrf(uint8_t bf, uint8_t bfa) {
        ASM_LOG("Emitting mcrf cr%u, %u to 0x%lx\n", bf, bfa, code_buf.pos_addr());
        CHECK_MASK(bf, 0b111U);
        CHECK_MASK(bfa, 0b111U);
        return xl_form(19, (uint8_t)(bf << 2), (uint8_t)(bfa << 2), 0, 0, 0);
    }

    // 3.3.3 Fixed-Point Store Instructions
    status_code std(uint8_t rs, uint8_t ra, uint16_t ds) {
        ASM_LOG("Emitting std r%u, 0x%x(r%u) to 0x%lx\n", rs, ds, ra, code_buf.pos_addr());
        return ds_form(62, rs, ra, ds, 0);
    }

    // 3.3.9 Fixed-Point Arithmetic Instructions
    status_code addi(uint8_t rt, uint8_t ra, int16_t si) {
        ASM_LOG("Emitting addi r%u, r%u, 0x%x to 0x%lx\n", rt, ra, si, code_buf.pos_addr());
        return d_form(14, rt, ra, (uint16_t)si);
    };

    status_code addis(uint8_t rt, uint8_t ra, int16_t si) {
        ASM_LOG("Emitting addis r%u, r%u, 0x%x to 0x%lx\n", rt, ra, si, code_buf.pos_addr());
        return d_form(15, rt, ra, (uint16_t)si);
    };

    status_code addpcis(uint8_t rt, int16_t d) {
        ASM_LOG("Emitting addpcis r%u, 0x%x to 0x%lx\n", rt, d, code_buf.pos_addr());
        return dx_form(19, rt, d, 2);
    }
    status_code lnia(uint8_t rt) { return addpcis(rt, 0); }

    status_code add_internal(uint8_t rt, uint8_t ra, uint8_t rb, bool modify_ov, bool modify_cr) {
        ASM_LOG("Emitting add%s%s r%u, r%u, r%u to 0x%lx\n", modify_ov?"o":"", modify_cr?".":"", rt, ra, rb, code_buf.pos_addr());
        return xo_form(31, rt, ra, rb, modify_ov, 266, modify_cr);
    }
    status_code add(uint8_t rt, uint8_t ra, uint8_t rb)   { return add_internal(rt, ra, rb, 0, 0); }
    status_code add_(uint8_t rt, uint8_t ra, uint8_t rb)  { return add_internal(rt, ra, rb, 0, 1); }
    status_code addo(uint8_t rt, uint8_t ra, uint8_t rb)  { return add_internal(rt, ra, rb, 1, 0); }
    status_code addo_(uint8_t rt, uint8_t ra, uint8_t rb) { return add_internal(rt, ra, rb, 1, 1); }

    status_code sub_internal(uint8_t rt, uint8_t rb, uint8_t ra, bool modify_ov, bool modify_cr) {
        ASM_LOG("Emitting sub%s%s r%u, r%u, r%u to 0x%lx\n", modify_ov?"o":"", modify_cr?".":"", rt, rb, ra, code_buf.pos_addr());
        return xo_form(31, rt, ra, rb, modify_ov, 40, modify_cr);
    }
    status_code sub(uint8_t rt, uint8_t rb, uint8_t ra)   { return sub_internal(rt, rb, ra, 0, 0); }
    status_code sub_(uint8_t rt, uint8_t rb, uint8_t ra)  { return sub_internal(rt, rb, ra, 0, 1); }
    status_code subo(uint8_t rt, uint8_t rb, uint8_t ra)  { return sub_internal(rt, rb, ra, 1, 0); }
    status_code subo_(uint8_t rt, uint8_t rb, uint8_t ra) { return sub_internal(rt, rb, ra, 1, 1); }

    status_code subc_internal(uint8_t rt, uint8_t rb, uint8_t ra, bool modify_ov, bool modify_cr) {
        ASM_LOG("Emitting subc%s%s r%u, r%u, r%u to 0x%lx\n", modify_ov?"o":"", modify_cr?".":"", rt, rb, ra, code_buf.pos_addr());
        return xo_form(31, rt, ra, rb, modify_ov, 8, modify_cr);
    }
    status_code subc(uint8_t rt, uint8_t rb, uint8_t ra)   { return subc_internal(rt, rb, ra, 0, 0); }
    status_code subc_(uint8_t rt, uint8_t rb, uint8_t ra)  { return subc_internal(rt, rb, ra, 0, 1); }
    status_code subco(uint8_t rt, uint8_t rb, uint8_t ra)  { return subc_internal(rt, rb, ra, 1, 0); }
    status_code subco_(uint8_t rt, uint8_t rb, uint8_t ra) { return subc_internal(rt, rb, ra, 1, 1); }

    status_code sube_internal(uint8_t rt, uint8_t rb, uint8_t ra, bool modify_ov, bool modify_cr) {
        ASM_LOG("Emitting sube%s%s r%u, r%u, r%u to 0x%lx\n", modify_ov?"o":"", modify_cr?".":"", rt, rb, ra, code_buf.pos_addr());
        return xo_form(31, rt, ra, rb, modify_ov, 136, modify_cr);
    }
    status_code sube(uint8_t rt, uint8_t rb, uint8_t ra)   { return sube_internal(rt, rb, ra, 0, 0); }
    status_code sube_(uint8_t rt, uint8_t rb, uint8_t ra)  { return sube_internal(rt, rb, ra, 0, 1); }
    status_code subeo(uint8_t rt, uint8_t rb, uint8_t ra)  { return sube_internal(rt, rb, ra, 1, 0); }
    status_code subeo_(uint8_t rt, uint8_t rb, uint8_t ra) { return sube_internal(rt, rb, ra, 1, 1); }

    status_code neg_internal(uint8_t rt, uint8_t ra, bool modify_ov, bool modify_cr) {
        ASM_LOG("Emitting neg%s%s r%u, r%u to 0x%lx\n", modify_ov?"o":"", modify_cr?".":"", rt, ra, code_buf.pos_addr());
        return xo_form(31, rt, ra, 0, modify_ov, 104, modify_cr);
    }
    status_code neg(uint8_t rt, uint8_t rb)   { return neg_internal(rt, rb, 0, 0); }
    status_code neg_(uint8_t rt, uint8_t rb)  { return neg_internal(rt, rb, 0, 1); }
    status_code nego(uint8_t rt, uint8_t rb)  { return neg_internal(rt, rb, 1, 0); }
    status_code nego_(uint8_t rt, uint8_t rb) { return neg_internal(rt, rb, 1, 1); }

    // 3.3.10 Fixed-Point Compare Instructions
    status_code cmp(uint8_t bf, uint8_t l, uint8_t ra, uint8_t rb) {
        CHECK_MASK(l, 1U);
        CHECK_MASK(bf, 0b111U);
        uint8_t rs = (uint8_t) (bf << (uint8_t)2U) | (l & (uint8_t)1U);
        ASM_LOG("Emitting cmp %u, %u, r%u, r%u to 0x%lu\n", bf, l, ra, rb, code_buf.pos_addr());
        return x_form(31, rs, ra, rb, 0, 0);
    }

    status_code cmpl(uint8_t bf, uint8_t l, uint8_t ra, uint8_t rb) {
        CHECK_MASK(l, 1U);
        CHECK_MASK(bf, 0b111U);
        uint8_t rs = (uint8_t) (bf << (uint8_t)2U) | (l & (uint8_t)1U);
        ASM_LOG("Emitting cmpl %u, %u, r%u, r%u to 0x%lu\n", bf, l, ra, rb, code_buf.pos_addr());
        return x_form(31, rs, ra, rb, 32, 0);
    }

    // 3.3.13 Fixed-Point Logical Instructions
    status_code andi_(uint8_t ra, uint8_t rs, uint16_t ui) {
        ASM_LOG("Emitting andi. r%u, r%u, 0x%x to 0x%lx\n", ra, rs, ui, code_buf.pos_addr());
        return d_form(28, rs, ra, ui);
    }

    status_code ori(uint8_t ra, uint8_t rs, uint16_t ui) {
        ASM_LOG("Emitting ori r%u, r%u, 0x%x to 0x%lx\n", ra, rs, ui, code_buf.pos_addr());
        return d_form(24, rs, ra, ui);
    }
    status_code nop() { return ori(0, 0, 0); }

    status_code oris(uint8_t ra, uint8_t rs, uint16_t ui) {
        ASM_LOG("Emitting oris r%u, r%u, 0x%x to 0x%lx\n", ra, rs, ui, code_buf.pos_addr());
        return d_form(25, rs, ra, ui);
    }

    status_code _or(uint8_t ra, uint8_t rs, uint8_t rb) {
        ASM_LOG("Emitting or r%u, r%u, r%u to 0x%lx\n", ra, rs, rb, code_buf.pos_addr());
        return x_form(31, rs, ra, rb, 444, 0);
    }
    status_code _or_(uint8_t ra, uint8_t rs, uint8_t rb) {
        ASM_LOG("Emitting or. r%u, r%u, r%u to 0x%lx\n", ra, rs, rb, code_buf.pos_addr());
        return x_form(31, rs, ra, rb, 444, 1);
    }
    status_code mr(uint8_t rx, uint8_t ry) { return _or(rx, ry, ry); }


    // 3.3.14 Fixed-Point Rotate and Shift Instruction
    status_code rlwinm(uint8_t ra, uint8_t rs, uint8_t sh, uint8_t mb, uint8_t me, bool modify_cr) {
        ASM_LOG("Emitting rlwinm%s r%u, r%u, %u, %u, %u to 0x%lx\n", modify_cr?".":"", ra, rs, sh, mb, me, code_buf.pos_addr());
        return m_form(21, rs, ra, sh, mb, me, modify_cr);
    }

    status_code rldicl(uint8_t ra, uint8_t rs, uint8_t sh, uint8_t me, bool modify_cr) {
        ASM_LOG("Emitting rldicl%s r%u, r%u, %u, %u to 0x%lx\n", modify_cr?".":"", ra, rs, sh, me, code_buf.pos_addr());
        return md_form(30, rs, ra, sh, me, 0, modify_cr);
    }
    status_code srdi(uint8_t rx, uint8_t ry, uint8_t n, bool modify_cr) {
        CHECK_MASK(n, 0b11111U);
        return rldicl(rx, ry, 64-n, n, modify_cr);
    }

    status_code rldicr(uint8_t ra, uint8_t rs, uint8_t sh, uint8_t me, bool modify_cr) {
        ASM_LOG("Emitting rldicr%s r%u, r%u, %u, %u to 0x%lx\n", modify_cr?".":"", ra, rs, sh, me, code_buf.pos_addr());
        return md_form(30, rs, ra, sh, me, 1, modify_cr);
    }
    status_code sldi(uint8_t rx, uint8_t ry, uint8_t n, bool modify_cr) {
        CHECK_MASK(n, 0b11111U);
        return rldicr(rx, ry, n, 63-n, modify_cr);
    }


    // 3.3.17 Move To/From System Register Instructions
    enum class SPR : uint16_t {
        XER = 1,
        DSCR = 3,
        LR = 8,
        CTR = 9
    };
    status_code mtspr(SPR spr, uint8_t rs) {
        ASM_LOG("Emitting mtspr r%u, %u to 0x%lx\n", rs, (uint16_t)spr, code_buf.pos_addr());
        uint16_t n = (uint16_t) (((uint16_t)spr & 0b11111U) << 5) | (((uint16_t)spr >> 5) & 0b11111U);
        return xfx_form(31, rs, n, 467);
    }

    status_code mfspr(uint8_t rt, SPR spr) {
        ASM_LOG("Emitting mfspr r%u, %u to 0x%lx\n", rt, (uint16_t)spr, code_buf.pos_addr());
        uint16_t n = (uint16_t) (((uint16_t)spr & 0b11111U) << 5) | (((uint16_t)spr >> 5) & 0b11111U);
        return xfx_form(31, rt, n, 339);
    }

    status_code mcrxrx(uint8_t bf) {
        ASM_LOG("Emitting mcrxrx %u to 0x%lx\n", code_buf.pos_addr());
        CHECK_MASK(bf, 0b111U);
        return x_form(31, (uint8_t)(bf << 2), 0, 0, 576, 0);
    }

    status_code mtocrf(uint8_t fxm, uint8_t rs) {
        ASM_LOG("Emitting mtcrf 0x%x, r%u to 0x%lx\n", fxm, rs, code_buf.pos_addr());
        return xfx_form(31, rs, (uint16_t)(fxm << 1) | (1 << 8), 144);
    }

    status_code mtcrf(uint8_t fxm, uint8_t rs) {
        ASM_LOG("Emitting mtcrf 0x%x, r%u to 0x%lx\n", fxm, rs, code_buf.pos_addr());
        return xfx_form(31, rs, (uint16_t)(fxm << 1), 144);
    }
    status_code mtcr(uint8_t rs) { return mtcrf(0xFF, rs); }

    status_code mfcr(uint8_t rt) {
        ASM_LOG("Emitting mfcr r%u to 0x%lx\n", rt, code_buf.pos_addr());
        return xfx_form(31, rt, 0, 19);
    }

    //
    // Book III
    //

    // 3.3.1 System Linkage Instructions
    status_code sc() {
        ASM_LOG("Emitting sc to 0x%lx\n", code_buf.pos_addr());
        return sc_form(17, 0);
    }
};

#ifndef KEEP_MASK_MACROS
#undef CHECK_MASK
#undef CHECK_MASK_SIGNED
#endif

}
}
