#pragma once

#include <util.h>
#include <allocators.h>

#include <vector>
#include <cstddef>
#include <cstdint>

namespace retrec {

namespace ppc64le {

class assembler {
    simple_region_writer &code_buf;

    status_code write32(uint32_t val) { return code_buf.write32(val); }

    status_code d_form(uint8_t po, uint8_t rt, uint8_t ra, uint16_t i);
    status_code ds_form(uint8_t po, uint8_t rs, uint8_t ra, uint16_t ds, uint8_t xo);
    status_code i_form(uint8_t po, int32_t li, uint8_t aa, uint8_t lk);
    status_code md_form(uint8_t po, uint8_t rs, uint8_t ra, uint8_t sh, uint8_t mb, uint8_t xo, uint8_t rc);
    status_code sc_form(uint8_t po, uint8_t lev);
    status_code xfx_form(uint8_t po, uint8_t rt, uint16_t spr, uint16_t xo);
    status_code xl_form(uint8_t po, uint8_t bt, uint8_t ba, uint8_t bb, uint16_t xo, uint8_t lk);

    // Extended mnemonics on p802
public:
    explicit assembler(simple_region_writer &code_buf_) : code_buf(code_buf_) {}

    //
    // Book I
    //

    // 2.4 Branch Instructions
    enum class BO : uint8_t {
        ALWAYS = 0b10100
    };

    status_code b_internal(int32_t li, uint8_t aa, uint8_t lk) {
        assert((li & 0b11U) == 0);
        log(LOGL_DEBUG, "Emitting b%s%s 0x%llx to 0x%lx\n",
            lk?"l":"", aa?"a":"", li, code_buf.pos_addr());
        return i_form(18, li>>2, aa, lk);
    }
    status_code b(int32_t li)   { return b_internal(li, 0, 0); }
    status_code ba(int32_t li)  { return b_internal(li, 1, 0); }
    status_code bl(int32_t li)  { return b_internal(li, 0, 1); }
    status_code bla(int32_t li) { return b_internal(li, 1, 1); }

    status_code bcctr_internal(BO bo, uint8_t bi, uint8_t bh, uint8_t lk) {
        log(LOGL_DEBUG, "Emitting bcctr%s %d %d %d to 0x%lx\n", lk?"l":"", (uint8_t)bo, bi, bh, code_buf.pos_addr());
        return xl_form(19, (uint8_t)bo, bi, bh, 528, lk);
    }
    status_code bcctr(BO bo, uint8_t bi, uint8_t bh)  { return bcctr_internal(bo, bi, bh, 0); }
    status_code bcctrl(BO bo, uint8_t bi, uint8_t bh) { return bcctr_internal(bo, bi, bh, 1); }
    status_code bctr()  { return bcctr_internal(BO::ALWAYS, 0, 0, 0); }
    status_code bctrl() { return bcctr_internal(BO::ALWAYS, 0, 0, 1); }

    // 3.3.3 Fixed-Point Store Instructions
    status_code std(uint8_t rs, uint8_t ra, uint16_t ds) {
        log(LOGL_DEBUG, "Emitting std r%u, 0x%x(r%u) to 0x%lx\n", rs, ds, ra, code_buf.pos_addr());
        return ds_form(62, rs, ra, ds, 0);
    }

    // 3.3.9 Fixed-Point Arithmetic Instructions
    status_code addi(uint8_t rt, uint8_t ra, int16_t si) {
        log(LOGL_DEBUG, "Emitting addi r%u, r%u, 0x%x to 0x%lx\n", rt, ra, si, code_buf.pos_addr());
        return d_form(14, rt, ra, si);
    };

    status_code addis(uint8_t rt, uint8_t ra, int16_t si) {
        log(LOGL_DEBUG, "Emitting addis r%u, r%u, 0x%x to 0x%lx\n", rt, ra, si, code_buf.pos_addr());
        return d_form(15, rt, ra, si);
    };

    // 3.3.13 Fixed-Point Logical Instructions
    status_code ori(uint8_t ra, uint8_t rs, uint16_t ui) {
        log(LOGL_DEBUG, "Emitting ori r%u, r%u, 0x%x to 0x%lx\n", ra, rs, ui, code_buf.pos_addr());
        return d_form(24, rs, ra, ui);
    };
    status_code nop() { return ori(0, 0, 0); }

    status_code oris(uint8_t ra, uint8_t rs, uint16_t ui) {
        log(LOGL_DEBUG, "Emitting oris r%u, r%u, 0x%x to 0x%lx\n", ra, rs, ui, code_buf.pos_addr());
        return d_form(25, rs, ra, ui);
    };

    // 3.3.14 Fixed-Point Rotate and Shift Instruction
    status_code rldicr(uint8_t ra, uint8_t rs, uint8_t sh, uint8_t me, uint8_t modify_cr) {
        log(LOGL_DEBUG, "Emitting rldicr%s r%u, r%u, %u, %u to 0x%lx\n", modify_cr?".":"", ra, rs, sh, me, code_buf.pos_addr());
        return md_form(30, rs, ra, sh, me, 1, modify_cr);
    }

    // 3.3.17 Move To/From System Register Instructions
    enum class SPR : uint16_t {
        XER = 1,
        DSCR = 3,
        LR = 8,
        CTR = 9
    };
    status_code mtspr(SPR spr, uint8_t rs) {
        log(LOGL_DEBUG, "Emitting mtspr r%u, %u to 0x%lx\n", rs, (uint16_t)spr, code_buf.pos_addr());
        uint16_t n = (((uint16_t)spr & 0b11111U) << 5) | (((uint16_t)spr >> 5) & 0b11111U);
        return xfx_form(31, rs, n, 467);
    }

    status_code mfspr(uint8_t rt, SPR spr) {
        log(LOGL_DEBUG, "Emitting mfspr r%u, %u to 0x%lx\n", rt, (uint16_t)spr, code_buf.pos_addr());
        uint16_t n = (((uint16_t)spr & 0b11111U) << 5) | (((uint16_t)spr >> 5) & 0b11111U);
        return xfx_form(31, rt, n, 339);
    }

    //
    // Book III
    //

    // 3.3.1 System Linkage Instructions
    status_code sc() {
        log(LOGL_DEBUG, "Emitting sc to 0x%lx\n", code_buf.pos_addr());
        return sc_form(17, 0);
    }
};

}
}