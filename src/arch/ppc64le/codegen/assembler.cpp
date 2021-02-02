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

#define KEEP_MASK_MACROS
#include <arch/ppc64le/codegen/assembler.h>

using namespace retrec;
using namespace retrec::ppc64le;

#define PO_MASK  (0b111111U)
#define REG_MASK (0b11111U)

instruction_stream_entry::~instruction_stream_entry() {}

assembler::~assembler() {}

status_code assembler::write32(uint32_t x) {
    return stream->write32(x);
}

status_code assembler::a_form(uint8_t po, uint8_t rt, uint8_t ra, uint8_t rb, uint8_t bc, uint8_t xo, uint8_t rc) {
    check_mask(po, PO_MASK);
    check_mask(rt, REG_MASK);
    check_mask(ra, REG_MASK);
    check_mask(rb, REG_MASK);
    check_mask(bc, REG_MASK);
    check_mask(xo, REG_MASK);
    check_mask(rc, 1U);
    uint32_t insn = (uint32_t)(po & PO_MASK) << (32-6U)
                    | (rt & REG_MASK) << (32-11U)
                    | (ra & REG_MASK) << (32-16U)
                    | (rb & REG_MASK) << (32-21U)
                    | (bc & REG_MASK) << (32-26U)
                    | (xo & REG_MASK) << (32-31U)
                    | (rc & 1U);
    return write32(insn);
}

status_code assembler::b_form(uint8_t po, uint8_t bo, uint8_t bi, int16_t bd, uint8_t aa, uint8_t lk) {
    constexpr uint16_t BD_MASK = 0b11111111111111U;
    check_mask(po, PO_MASK);
    check_mask(bo, REG_MASK);
    check_mask(bi, REG_MASK);
    check_mask(bd, BD_MASK);
    check_mask(aa, 1U);
    check_mask(lk, 1U);
    uint32_t insn = (uint32_t)(po & PO_MASK) << (32-6U)
                    | (bo & REG_MASK) << (32-11U)
                    | (bi & REG_MASK) << (32-16U)
                    | (bd & BD_MASK) << (32-30U)
                    | (aa & 1U) << (32-31U)
                    | (lk & 1U);
    return write32(insn);
}

status_code assembler::d_form(uint8_t po, uint8_t rt, uint8_t ra, int16_t i) {
    check_mask(po, PO_MASK);
    check_mask(rt, REG_MASK);
    check_mask(ra, REG_MASK);
    uint32_t insn = (uint32_t)(po & PO_MASK) << (32-6U)
                    | (rt & REG_MASK) << (32-11U)
                    | (ra & REG_MASK) << (32-16U)
                    | (i & 0xFFFFU);
    return write32(insn);
}

status_code assembler::ds_form(uint8_t po, uint8_t rs, uint8_t ra, int16_t ds, uint8_t xo) {
    constexpr uint32_t DS_MASK = 0b11111111111111U;
    check_mask(po, PO_MASK);
    check_mask(rs, REG_MASK);
    check_mask(ra, REG_MASK);
    check_mask(ds >> 2U, DS_MASK);
    check_mask(xo, 0b11U);
    uint32_t insn = (uint32_t)(po & PO_MASK) << (32-6U)
                    | (rs & REG_MASK) << (32-11U)
                    | (ra & REG_MASK) << (32-16U)
                    | ((ds >> 2U) & DS_MASK) << (32-30U)
                    | (xo & 0b11U);
    return write32(insn);
}

status_code assembler::dq_form(uint8_t po, uint8_t t, uint8_t ra, int16_t dq, uint8_t tx, uint8_t xo) {
    constexpr uint8_t XO_MASK = 0b111U;
    constexpr uint16_t DQ_MASK = 0b111111111111U;
    check_mask(po, PO_MASK);
    check_mask(t,  REG_MASK);
    check_mask(ra, REG_MASK);
    check_mask(dq >> 4U, DQ_MASK);
    check_mask(tx, 1U);
    check_mask(xo, XO_MASK);
    uint32_t insn = (uint32_t)(po & PO_MASK) << (32-6U)
                    | (t & REG_MASK) << (32-11U)
                    | (ra & REG_MASK) << (32-16U)
                    | ((dq >> 4U) & DQ_MASK) << (32-28U)
                    | (tx & 1U) << (32-29U)
                    | (xo & XO_MASK);
    return write32(insn);
}

status_code assembler::dx_form(uint8_t po, uint8_t rt, int16_t d, uint8_t xo) {
    constexpr uint32_t XO_MASK = 0b11111U;
    check_mask(po, PO_MASK);
    check_mask(rt, REG_MASK);
    check_mask(xo, XO_MASK);

    uint32_t d0 = d >> 6 & 0b1111111111;
    uint32_t d1 = (d >> 1) & 0b11111U;
    uint32_t d2 = d & 1U;

    uint32_t insn = (uint32_t)(po & PO_MASK) << (32-6U)
                    | (rt & REG_MASK) << (32-11U)
                    | d1 << (32-16U)
                    | d0 << (32-26U)
                    | (xo & XO_MASK) << (32-31U)
                    | d2;
    return write32(insn);
}

status_code assembler::i_form(uint8_t po, int32_t li, uint8_t aa, uint8_t lk) {
    constexpr uint32_t LI_MASK = 0b111111111111111111111111; // 24-bit
    check_mask(po, PO_MASK);
    check_mask(li, LI_MASK);
    check_mask(aa, 1U);
    check_mask(lk, 1U);
    uint32_t insn = (uint32_t)(po & PO_MASK) << (32-6U)
                    | (li & LI_MASK) << (32-30U)
                    | (aa & 1U) << (32-31U)
                    | (lk & 1U);
    return write32(insn);
}

status_code assembler::md_form(uint8_t po, uint8_t rs, uint8_t ra, uint8_t sh, uint8_t mb, uint8_t xo, uint8_t rc) {
    constexpr uint8_t SH_MASK = 0b111111U;
    constexpr uint8_t MB_MASK = 0b111111U;
    constexpr uint8_t XO_MASK = 0b111U;
    check_mask(po, PO_MASK);
    check_mask(rs, REG_MASK);
    check_mask(ra, REG_MASK);
    check_mask(sh, SH_MASK);
    check_mask(mb, MB_MASK);
    check_mask(xo, XO_MASK);
    check_mask(rc, 1U);
    uint32_t insn = (uint32_t)(po & PO_MASK) << (32-6U)
                    | (rs & REG_MASK) << (32-11U)
                    | (ra & REG_MASK) << (32-16U)
                    | (sh & 0b11111U) << (32-21U)
                    | (((mb >> 5U) & 1U) | ((mb & 0b11111U) << 1U)) << (32-27U)
                    | (xo & XO_MASK) << (32-30U)
                    | ((sh >> 5U) & 1U) << (32-31U)
                    | (rc & 1U);
    return write32(insn);
}

status_code assembler::mds_form(uint8_t po, uint8_t rs, uint8_t ra, uint8_t rb, uint8_t mb, uint8_t xo, uint8_t rc) {
    constexpr uint8_t MB_MASK = 0b111111U;
    constexpr uint8_t XO_MASK = 0b1111U;
    check_mask(po, PO_MASK);
    check_mask(rs, REG_MASK);
    check_mask(ra, REG_MASK);
    check_mask(rb, REG_MASK);
    check_mask(mb, MB_MASK);
    check_mask(xo, XO_MASK);
    check_mask(rc, 1U);
    uint32_t insn = (uint32_t)(po & PO_MASK) << (32-6U)
                    | (rs & REG_MASK) << (32-11U)
                    | (ra & REG_MASK) << (32-16U)
                    | (rb & REG_MASK) << (32-21U)
                    | (mb & MB_MASK) << (32-27U)
                    | (xo & XO_MASK) << (32-31U)
                    | (rc & 1U);
    return write32(insn);
}

status_code assembler::m_form(uint8_t po, uint8_t rs, uint8_t ra, uint8_t sh, uint8_t mb, uint8_t me, uint8_t rc) {
    constexpr uint8_t SH_MASK = 0b11111U;
    constexpr uint8_t MB_MASK = 0b11111U;
    constexpr uint8_t ME_MASK = 0b11111U;
    check_mask(po, PO_MASK);
    check_mask(rs, REG_MASK);
    check_mask(ra, REG_MASK);
    check_mask(sh, SH_MASK);
    check_mask(mb, MB_MASK);
    check_mask(me, ME_MASK);
    check_mask(rc, 1U);
    uint32_t insn = (uint32_t)(po & PO_MASK) << (32-6U)
                    | (rs & REG_MASK) << (32-11U)
                    | (ra & REG_MASK) << (32-16U)
                    | (sh & SH_MASK) << (32-21U)
                    | (mb & MB_MASK) << (32-26U)
                    | (me & ME_MASK) << (32-31U)
                    | (rc & 1U);
    return write32(insn);
}

status_code assembler::sc_form(uint8_t po, uint8_t lev) {
    check_mask(po, PO_MASK);
    uint32_t insn = (uint32_t)(po & PO_MASK) << (32-6U)
                    | (lev & 0b1111111U) << (32-20U)
                    | 0b10U;
    return write32(insn);
}

status_code assembler::xfx_form(uint8_t po, uint8_t rt, uint16_t spr, uint16_t xo) {
    constexpr uint16_t SPR_MASK = 0b1111111111U;
    constexpr uint16_t XO_MASK = 0b1111111111U;
    check_mask(po, PO_MASK);
    check_mask(rt, REG_MASK);
    check_mask(spr, SPR_MASK);
    check_mask(xo, XO_MASK);
    uint32_t insn = (uint32_t)(po & PO_MASK) << (32-6U)
                    | (rt & REG_MASK) << (32-11U)
                    | (spr & SPR_MASK) << (32-21U)
                    | (xo & XO_MASK) << (32-31U);
    return write32(insn);
}

status_code assembler::xl_form(uint8_t po, uint8_t bt, uint8_t ba, uint8_t bb, uint16_t xo, uint8_t lk) {
    constexpr uint16_t XO_MASK = 0b1111111111U;
    check_mask(po, PO_MASK);
    check_mask(bt, REG_MASK);
    check_mask(ba, REG_MASK);
    check_mask(bb, REG_MASK);
    check_mask(xo, XO_MASK);
    check_mask(lk, 1U);
    uint32_t insn = (uint32_t)(po & PO_MASK) << (32-6U)
                    | (bt & REG_MASK) << (32-11U)
                    | (ba & REG_MASK) << (32-16U)
                    | (bb & REG_MASK) << (32-21U)
                    | (xo & XO_MASK) << (32-31U)
                    | (lk & 1U);
    return write32(insn);
}

status_code assembler::xo_form(uint8_t po, uint8_t rt, uint8_t ra, uint8_t rb, uint8_t oe, uint16_t xo, uint8_t rc) {
    constexpr uint16_t XO_MASK = 0b111111111U;
    check_mask(po, PO_MASK);
    check_mask(rt, REG_MASK);
    check_mask(ra, REG_MASK);
    check_mask(rb, REG_MASK);
    check_mask(oe, 1U);
    check_mask(xo, XO_MASK);
    check_mask(rc, 1U);
    uint32_t insn = (uint32_t)(po & PO_MASK) << (32-6U)
                    | (rt & REG_MASK) << (32-11U)
                    | (ra & REG_MASK) << (32-16U)
                    | (rb & REG_MASK) << (32-21U)
                    | (oe & 1U) << (32-22U)
                    | (xo & XO_MASK) << (32-31U)
                    | (rc & 1U);
    return write32(insn);
}

status_code assembler::x_form(uint8_t po, uint8_t rs, uint8_t ra, uint8_t rb, uint16_t xo, uint8_t rc) {
    constexpr uint16_t XO_MASK = 0b1111111111U;
    check_mask(po, PO_MASK);
    check_mask(rs, REG_MASK);
    check_mask(ra, REG_MASK);
    check_mask(rb, REG_MASK);
    check_mask(xo, XO_MASK);
    check_mask(rc, 1U);
    uint32_t insn = (uint32_t)(po & PO_MASK) << (32-6U)
                    | (rs & REG_MASK) << (32-11U)
                    | (ra & REG_MASK) << (32-16U)
                    | (rb & REG_MASK) << (32-21U)
                    | (xo & XO_MASK)  << (32-31U)
                    | (rc & 1U);
    return write32(insn);
}

status_code assembler::xs_form(uint8_t po, uint8_t rs, uint8_t ra, uint8_t sh, uint16_t xo, uint8_t rc) {
    constexpr uint16_t XO_MASK = 0b111111111U;
    constexpr uint8_t SH_MASK = 0b111111U;
    check_mask(po, PO_MASK);
    check_mask(rs, REG_MASK);
    check_mask(ra, REG_MASK);
    check_mask(sh, SH_MASK);
    check_mask(xo, XO_MASK);
    uint8_t sh0 = sh & 0b11111U;
    uint8_t sh1 = (sh >> 5) & 1;
    uint32_t insn = (uint32_t)(po & PO_MASK) << (32-6U)
                    | (rs & REG_MASK) << (32-11U)
                    | (ra & REG_MASK) << (32-16U)
                    | (sh0)           << (32-21U)
                    | (xo & XO_MASK)  << (32-30U)
                    | (sh1)           << (32-31U)
                    | (rc & 1U);
    return write32(insn);
}

status_code assembler::xx3_form(uint8_t po, uint8_t t, uint8_t a, uint8_t b, uint16_t xo, bool ax, bool bx, bool tx) {
    constexpr uint16_t XO_MASK = 0b11111111;
    check_mask(po, PO_MASK);
    check_mask(t, REG_MASK);
    check_mask(a, REG_MASK);
    check_mask(b, REG_MASK);
    check_mask(xo, XO_MASK);
    check_mask(ax, 1U);
    check_mask(bx, 1U);
    check_mask(tx, 1U);
    uint32_t insn = (uint32_t)(po & PO_MASK) << (32-6U)
                    | (t & REG_MASK) << (32-11U)
                    | (a & REG_MASK) << (32-16U)
                    | (b & REG_MASK) << (32-21U)
                    | (xo & XO_MASK) << (32-29U)
                    | (ax & 1U) << (32-30U)
                    | (bx & 1U) << (32-31U)
                    | (tx & 1U);
    return write32(insn);
}
