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

/**
 * This file contains specializations of codegen_ppc64le methods for X86_64 targets
 */

#include <arch/ppc64le/codegen/codegen_ppc64le.h>
#include <arch/ppc64le/codegen/codegen_ppc64le_internal.h>
#include <arch/ppc64le/codegen/assembler.h>

using namespace retrec;
using namespace retrec::ppc64le;

// Because of how strange the x87 FPU is, float-specific loads/stores need to be handled entirely separately.
template <>
void codegen_ppc64le<TargetTraitsX86_64>::llir$loadstore_float(gen_context &ctx, const llir::Insn &insn) {
    pr_debug("$loadstore_float\n");
    assert(insn.src_cnt == 1 && insn.dest_cnt == 1);

    const llir::Operand &st_op = (insn.loadstore().op == llir::LoadStore::Op::FLOAT_LOAD)
                                    ? insn.dest[0] : insn.src[0];
    const llir::Operand &mem_op = (insn.loadstore().op == llir::LoadStore::Op::FLOAT_LOAD)
                                    ? insn.src[0] : insn.dest[0];
    bool mem_op_is_x87 = [&] {
        switch(mem_op.memory().x86_64().base.x86_64) {
            case llir::X86_64Register::ST0:
            case llir::X86_64Register::ST1:
            case llir::X86_64Register::ST2:
            case llir::X86_64Register::ST3:
            case llir::X86_64Register::ST4:
            case llir::X86_64Register::ST5:
            case llir::X86_64Register::ST6:
            case llir::X86_64Register::ST7:
                return true;
            default:
                return false;
        }
    }();

    // FLD
    //   OP  - FLOAT_LOAD
    //   DST - r11.x86_64.st_top
    //   SRC - mem/st(x)
    //
    // FSTP
    //   OP  - FLOAT_STORE
    //   DST - mem/st(x)
    //   SRC - r11.x86_64.st_top

    // Allocate a register for storing the X87 stack TOP offset
    assert(st_op.memory().x86_64().base.x86_64 == llir::X86_64Register::ST0);
    auto st_top_offset_reg = ctx.reg_allocator().allocate_gpr();
    ctx.assembler->lhz(st_top_offset_reg.gpr(), GPR_FIXED_RUNTIME_CTX, offsetof(runtime_context_ppc64le, x86_64_ucontext.st_top_offset));

    // Decrement the stack pointer if requested
    switch (st_op.memory().update) {
        case llir::MemOp::Update::PRE:
        {
            assert(insn.loadstore().op == llir::LoadStore::Op::FLOAT_LOAD);
            assert(st_op.memory().x86_64().disp == -80);

            // Decrement the stack pointer
            ctx.assembler->addi(st_top_offset_reg.gpr(), st_top_offset_reg.gpr(), -(int16_t)sizeof(cpu_context_x86_64::x87_reg));

            // Apply offset mask to account for underflow
            auto tmp = ctx.reg_allocator().allocate_gpr();
            ctx.assembler->li(tmp.gpr(), cpu_context_x86_64::st_offset_mask);
            ctx.assembler->_and(st_top_offset_reg.gpr(), st_top_offset_reg.gpr(), tmp.gpr());

            // Write the new offset back
            ctx.assembler->sth(st_top_offset_reg.gpr(), GPR_FIXED_RUNTIME_CTX, offsetof(runtime_context_ppc64le, x86_64_ucontext.st_top_offset));
            break;
        }

        case llir::MemOp::Update::POST:
            assert(insn.loadstore().op == llir::LoadStore::Op::FLOAT_STORE);
            TODO();

        case llir::MemOp::Update::NONE:
            break;
    }

    auto increment_mem_op = [](const llir::Operand &mem_op, int64_t amount) {
        auto copy = mem_op;
        // Will this work in all scenarios?
        copy.memory().x86_64().disp += amount;
        return copy;
    };

    constexpr int16_t x87_base_off = offsetof(runtime_context_ppc64le, x86_64_ucontext.x87);

    // Perform load/store operation
    auto tmp = ctx.reg_allocator().allocate_gpr();
    if (insn.loadstore().op == llir::LoadStore::Op::FLOAT_LOAD) {
        switch (mem_op.width) {
            case llir::Operand::Width::_80BIT:
                if (mem_op_is_x87) {
                    int16_t offset = 16 * ((int16_t)mem_op.memory().x86_64().base.x86_64 - (int16_t)llir::X86_64Register::ST0);
                    if (st_op.memory().update == llir::MemOp::Update::PRE)
                        offset += 16;

                    // Add the offset a src register and mask for overflow
                    auto src_st_reg = ctx.reg_allocator().allocate_gpr();
                    ctx.assembler->addi(src_st_reg.gpr(), st_top_offset_reg.gpr(), offset);
                    ctx.assembler->li(tmp.gpr(), cpu_context_x86_64::st_offset_mask);
                    ctx.assembler->_and(src_st_reg.gpr(), src_st_reg.gpr(), tmp.gpr());

                    // Add GPR_FIXED_RUNTIME_CTX to src and dst pointer registers
                    ctx.assembler->add(src_st_reg.gpr(), src_st_reg.gpr(), GPR_FIXED_RUNTIME_CTX);
                    ctx.assembler->add(st_top_offset_reg.gpr(), st_top_offset_reg.gpr(), GPR_FIXED_RUNTIME_CTX);

                    // Load src.lo into tmp and store into dest.lo
                    ctx.assembler->ld(tmp.gpr(), src_st_reg.gpr(), x87_base_off + 0);
                    ctx.assembler->std(tmp.gpr(), st_top_offset_reg.gpr(), x87_base_off + 0);

                    // Load src.hi into tmp and store into dest.hi
                    ctx.assembler->lhz(tmp.gpr(), src_st_reg.gpr(), x87_base_off + 8);
                    ctx.assembler->sth(tmp.gpr(), st_top_offset_reg.gpr(), x87_base_off + 8);
                } else {
                    // Add GPR_FIXED_RUNTIME_CTX to the offset reg to st_top_offset_reg. This way
                    // the actual x87 reg can be accessed from an immediate displacement from the register
                    ctx.assembler->add(st_top_offset_reg.gpr(), st_top_offset_reg.gpr(), GPR_FIXED_RUNTIME_CTX);

                    // Copy the first 8 bytes of the fpu reg and store it
                    macro$loadstore_gpr(ctx, tmp.gpr(), mem_op, llir::LoadStore::Op::LOAD,
                                        llir::Register::Mask::Full64, true, insn);
                    ctx.assembler->std(tmp.gpr(), st_top_offset_reg.gpr(), x87_base_off + 0);

                    // Increment the memop by 8 bytes and copy the last 2 bytes
                    auto new_mem_op = increment_mem_op(mem_op, 8);
                    macro$loadstore_gpr(ctx, tmp.gpr(), new_mem_op, llir::LoadStore::Op::LOAD,
                                        llir::Register::Mask::LowLow16, true, insn);
                    ctx.assembler->sth(tmp.gpr(), st_top_offset_reg.gpr(), x87_base_off + 8);
                }
                break;

            case llir::Operand::Width::_64BIT:
            case llir::Operand::Width::_32BIT:
                TODO(); // Load from m32fp/m64fp

            default:
                ASSERT_NOT_REACHED();
        }
    } else {
        TODO();
    }
}

// Specialization of macro$loadstore for x86_64 targets
template <>
void codegen_ppc64le<TargetTraitsX86_64>::macro$loadstore(gen_context &ctx, const llir::Register &reg,
                                                          const llir::Operand &mem_op, const llir::Insn &insn,
                                                          const llir::LoadStore &loadstore) {
    auto mem = mem_op.memory();
    auto update = mem.update;
    auto &x86_64 = mem.x86_64();
    auto extension = loadstore.extension;
    auto op = loadstore.op;
    bool sign_ext = extension == llir::Extension::SIGN;
    bool vector = (op == llir::LoadStore::Op::VECTOR_LOAD || op == llir::LoadStore::Op::VECTOR_STORE);
    uint64_t tls_base_off = 0;
    using AllocatedRegT = typename register_allocator<TargetTraitsX86_64>::AllocatedRegT;

    // Partially handle segment for TLS
    switch (mem.x86_64().segment.x86_64) {
        case llir::X86_64Register::FS:
            // Use the emulated CPU context's FS register as the TLS base
            tls_base_off = offsetof(runtime_context_ppc64le, x86_64_ucontext)
                             + offsetof(cpu_context_x86_64, segments[0]);
            break;
        case llir::X86_64Register::GS:
            // Use the emulated CPU context's FS register as the TLS base
            tls_base_off = offsetof(runtime_context_ppc64le, x86_64_ucontext)
                             + offsetof(cpu_context_x86_64, segments[1]);
            break;
        case llir::X86_64Register::INVALID:
            // No segment, treat normally
            break;
        default:
            TODO();
    }

    // Wrappers for load{displacement, indexed} with {zero, sign} extension, with emulation
    // for instructions that don't exist.
    auto ld    = [&](auto a, auto b, auto c) { ctx.assembler->ld(a, b, c); };
    auto ldu   = [&](auto a, auto b, auto c) { ctx.assembler->ldu(a, b, c); };
    auto ldx   = [&](auto a, auto b, auto c) { ctx.assembler->ldx(a, b, c); };
    auto ldux  = [&](auto a, auto b, auto c) { ctx.assembler->ldux(a, b, c); };

    auto lwz   = [&](auto a, auto b, auto c) { ctx.assembler->lwz(a, b, c); };
    auto lwzu  = [&](auto a, auto b, auto c) { ctx.assembler->lwzu(a, b, c); };
    auto lwzx  = [&](auto a, auto b, auto c) { ctx.assembler->lwzx(a, b, c); };
    auto lwzux = [&](auto a, auto b, auto c) { ctx.assembler->lwzux(a, b, c); };
    auto lwa   = [&](auto a, auto b, auto c) { ctx.assembler->lwa(a, b, c); };
    auto lwau  = [&](auto a, auto b, auto c) { ctx.assembler->lwa(a, b, c); ctx.assembler->addi(b, b, c); };
    auto lwax  = [&](auto a, auto b, auto c) { ctx.assembler->lwax(a, b, c); };
    auto lwaux = [&](auto a, auto b, auto c) { ctx.assembler->lwaux(a, b, c); };

    auto lhz   = [&](auto a, auto b, auto c) { ctx.assembler->lhz(a, b, c); };
    auto lhzu  = [&](auto a, auto b, auto c) { ctx.assembler->lhzu(a, b, c); };
    auto lhzx  = [&](auto a, auto b, auto c) { ctx.assembler->lhzx(a, b, c); };
    auto lhzux = [&](auto a, auto b, auto c) { ctx.assembler->lhzux(a, b, c); };
    auto lha   = [&](auto a, auto b, auto c) { ctx.assembler->lha(a, b, c); };
    auto lhau  = [&](auto a, auto b, auto c) { ctx.assembler->lhau(a, b, c); };
    auto lhax  = [&](auto a, auto b, auto c) { ctx.assembler->lhax(a, b, c); };
    auto lhaux = [&](auto a, auto b, auto c) { ctx.assembler->lhaux(a, b, c); };

    auto lbz   = [&](auto a, auto b, auto c) { ctx.assembler->lbz(a, b, c); };
    auto lbzu  = [&](auto a, auto b, auto c) { ctx.assembler->lbzu(a, b, c); };
    auto lbzx  = [&](auto a, auto b, auto c) { ctx.assembler->lbzx(a, b, c); };
    auto lbzux = [&](auto a, auto b, auto c) { ctx.assembler->lbzux(a, b, c); };
    auto lba   = [&](auto a, auto b, auto c) { ctx.assembler->lbz(a, b, c); ctx.assembler->extsb(a, a); };
    auto lbau  = [&](auto a, auto b, auto c) { ctx.assembler->lbzu(a, b, c); ctx.assembler->extsb(a, a); };
    auto lbax  = [&](auto a, auto b, auto c) { ctx.assembler->lbzx(a, b, c); ctx.assembler->extsb(a, a); };
    auto lbaux = [&](auto a, auto b, auto c) { ctx.assembler->lbzux(a, b, c); ctx.assembler->extsb(a, a); };

    auto vsx_loadx_lowlow32 = [&](auto a, auto b, auto c) {
        auto tmp = ctx.reg_allocator().allocate_gpr();
        ctx.assembler->lwzx(tmp.gpr(), b, c);
        ctx.assembler->mtvsrdd(a, 0, tmp.gpr());
    };

    auto vsx_storex_lowlow32 = [&](auto a, auto b, auto c) {
        auto tmp = ctx.reg_allocator().allocate_gpr();
        ctx.assembler->mfvsrld(tmp.gpr(), a);
        ctx.assembler->stwx(tmp.gpr(), b, c);
    };

// Helpers to call the appropriate loadstore op depending on whether `update` is set or not
#define LOAD_DISP(op, ...) ((update == llir::MemOp::Update::PRE) ? op ## u(__VA_ARGS__) : op(__VA_ARGS__))
#define LOAD_INDEXED(op, ...) ((update == llir::MemOp::Update::PRE) ? op ## ux(__VA_ARGS__) : op ## x(__VA_ARGS__))
#define STORE_DISP(op, ...) ((update == llir::MemOp::Update::PRE) ? ctx.assembler->op ## u(__VA_ARGS__) : ctx.assembler->op(__VA_ARGS__))
#define STORE_INDEXED(op, ...) ((update == llir::MemOp::Update::PRE) ? ctx.assembler->op ## ux(__VA_ARGS__) : ctx.assembler->op ## x(__VA_ARGS__))

    // Wrappers for performing loads with appropriate update and extension
    auto ld_  = [&](auto dest, auto ra, auto disp) { return LOAD_DISP(ld, dest, ra, disp); };
    auto lw_  = [&](auto dest, auto ra, auto disp) { return sign_ext ? LOAD_DISP(lwa, dest, ra, disp) : LOAD_DISP(lwz, dest, ra, disp); };
    auto lh_  = [&](auto dest, auto ra, auto disp) { return sign_ext ? LOAD_DISP(lha, dest, ra, disp) : LOAD_DISP(lhz, dest, ra, disp); };
    auto lb_  = [&](auto dest, auto ra, auto disp) { return sign_ext ? LOAD_DISP(lba, dest, ra, disp) : LOAD_DISP(lbz, dest, ra, disp); };
    auto ldx_ = [&](auto dest, auto ra, auto disp) { return LOAD_INDEXED(ld, dest, ra, disp); };
    auto lwx_ = [&](auto dest, auto ra, auto disp) { return sign_ext ? LOAD_INDEXED(lwa, dest, ra, disp) : LOAD_INDEXED(lwz, dest, ra, disp); };
    auto lhx_ = [&](auto dest, auto ra, auto disp) { return sign_ext ? LOAD_INDEXED(lha, dest, ra, disp) : LOAD_INDEXED(lhz, dest, ra, disp); };
    auto lbx_ = [&](auto dest, auto ra, auto disp) { return sign_ext ? LOAD_INDEXED(lba, dest, ra, disp) : LOAD_INDEXED(lbz, dest, ra, disp); };

#undef LOAD_DISP
#undef LOAD_INDEXED

    auto loadstore_disp = [&](const AllocatedRegT &r, gpr_t ra, int16_t disp) {
        switch (op) {
            case llir::LoadStore::Op::LOAD:
            {
                gpr_t dest = r.gpr();
                register_allocator<TargetTraitsX86_64>::AllocatedRegT tmp;

                if (!reg.zero_others) {
                    tmp = ctx.reg_allocator().allocate_gpr();
                    dest = tmp.gpr();
                }

                switch (reg.mask) {
                    case llir::Register::Mask::Full64: ld_(dest, ra, disp); break;
                    case llir::Register::Mask::Low32: lw_(dest, ra, disp); break;
                    case llir::Register::Mask::LowLow16: lh_(dest, ra, disp); break;
                    case llir::Register::Mask::LowLowLow8: lb_(dest, ra, disp); break;
                    case llir::Register::Mask::LowLowHigh8:
                    {
                        // FIXME: There's probably a more intelligent way to do this
                        auto temp = ctx.reg_allocator().allocate_gpr();
                        lb_(temp.gpr(), ra, disp);
                        macro$move_register_masked(*ctx.assembler, r.gpr(), temp.gpr(),
                                                   llir::Register::Mask::LowLowLow8,
                                                   llir::Register::Mask::LowLowHigh8, false, false);
                        assert(!reg.zero_others);
                        return; // Skip zero_others cleanup code
                    }
                    default:
                        ASSERT_NOT_REACHED();
                }

                if (!reg.zero_others)
                    macro$move_register_masked(*ctx.assembler, r.gpr(), dest, reg.mask, reg.mask, false, false);

                break;
            }

            case llir::LoadStore::Op::STORE:
            {
                switch (reg.mask) {
                    case llir::Register::Mask::Full64: STORE_DISP(std, r.gpr(), ra, disp); break;
                    case llir::Register::Mask::Low32: STORE_DISP(stw, r.gpr(), ra, disp); break;
                    case llir::Register::Mask::LowLow16: STORE_DISP(sth, r.gpr(), ra, disp); break;
                    case llir::Register::Mask::LowLowLow8: STORE_DISP(stb, r.gpr(), ra, disp); break;
                    case llir::Register::Mask::LowLowHigh8:
                    {
                        auto temp = ctx.reg_allocator().allocate_gpr();
                        macro$move_register_masked(*ctx.assembler, temp.gpr(), r.gpr(),
                                                   llir::Register::Mask::LowLowHigh8,
                                                   llir::Register::Mask::LowLowLow8, false, false);
                        STORE_DISP(stb, temp.gpr(), ra, disp);
                        break;
                    }
                    default:
                        ASSERT_NOT_REACHED();
                }

                break;
            }

            case llir::LoadStore::Op::LEA:
            {
                // Load calculated address into reg
                ctx.assembler->addi(r.gpr(), ra, disp);
                break;
            }

            case llir::LoadStore::Op::VECTOR_LOAD:
            {
                // We don't need to worry about source memory alignment since the kernel will automatically
                // correct unaligned accesses for us. This is probably slower than manually emitting an unaligned
                // load ourselves, but it's easier so it works for now.
                assert(extension == llir::Extension::NONE);
                assert(update == llir::MemOp::Update::NONE);
                assert(reg.zero_others);
                switch (reg.mask) {
                    case llir::Register::Mask::Vector128Full: ctx.assembler->lxv(r.vsr(), ra, disp); break;
                    case llir::Register::Mask::Vector128High64:
                    case llir::Register::Mask::Vector128Low64:
                    case llir::Register::Mask::Vector128LowLow32:
                        // Non-128-bit loads don't have displacement forms
                    default:
                        ASSERT_NOT_REACHED();
                }

                break;
            }

            case llir::LoadStore::Op::VECTOR_STORE:
            {
                assert(extension == llir::Extension::NONE);
                assert(update == llir::MemOp::Update::NONE);
                switch (reg.mask) {
                    case llir::Register::Mask::Vector128Full: ctx.assembler->stxv(r.vsr(), ra, disp); break;
                    case llir::Register::Mask::Vector128High64:
                    case llir::Register::Mask::Vector128Low64:
                    case llir::Register::Mask::Vector128LowLow32:
                        // Non-128-bit stores don't have displacement forms
                    default:
                        ASSERT_NOT_REACHED();
                }

                break;
            }

            default:
                ASSERT_NOT_REACHED();
        }
    };

    auto loadstore_indexed = [&](const AllocatedRegT &r, gpr_t ra, gpr_t rb) {
        switch (op) {
            case llir::LoadStore::Op::LOAD:
            {
                gpr_t dest = r.gpr();
                register_allocator<TargetTraitsX86_64>::AllocatedRegT tmp;
                if (!reg.zero_others) {
                    tmp = ctx.reg_allocator().allocate_gpr();
                    dest = tmp.gpr();
                }

                switch (reg.mask) {
                    case llir::Register::Mask::Full64: ldx_(dest, ra, rb); break;
                    case llir::Register::Mask::Low32: lwx_(dest, ra, rb); break;
                    case llir::Register::Mask::LowLow16: lhx_(dest, ra, rb); break;
                    case llir::Register::Mask::LowLowLow8: lbx_(dest, ra, rb); break;
                    case llir::Register::Mask::LowLowHigh8:
                    {
                        auto temp = ctx.reg_allocator().allocate_gpr();
                        lbx_(temp.gpr(), ra, rb);
                        macro$move_register_masked(*ctx.assembler, r.gpr(), temp.gpr(),
                                                   llir::Register::Mask::LowLowLow8,
                                                   llir::Register::Mask::LowLowHigh8, false, false);
                        assert(!reg.zero_others);
                        return; // Skip zero_others cleanup code
                    }
                    default:
                        ASSERT_NOT_REACHED();
                }

                if (!reg.zero_others)
                    macro$move_register_masked(*ctx.assembler, r.gpr(), dest, reg.mask, reg.mask, false, false);

                break;
            }
            case llir::LoadStore::Op::STORE:
            {
                switch (reg.mask) {
                    case llir::Register::Mask::Full64: STORE_INDEXED(std, r.gpr(), ra, rb); break;
                    case llir::Register::Mask::Low32: STORE_INDEXED(stw, r.gpr(), ra, rb); break;
                    case llir::Register::Mask::LowLow16: STORE_INDEXED(sth, r.gpr(), ra, rb); break;
                    case llir::Register::Mask::LowLowLow8: STORE_INDEXED(stb, r.gpr(), ra, rb); break;
                    case llir::Register::Mask::LowLowHigh8:
                    {
                        auto temp = ctx.reg_allocator().allocate_gpr();
                        macro$move_register_masked(*ctx.assembler, temp.gpr(), r.gpr(),
                                                   llir::Register::Mask::LowLowHigh8,
                                                   llir::Register::Mask::LowLowLow8, false, false);
                        STORE_INDEXED(stb, temp.gpr(), ra, rb);
                        break;
                    }
                    default:
                        ASSERT_NOT_REACHED();
                }

                break;
            }

            case llir::LoadStore::Op::LEA:
                // Load calculated address into reg
                ctx.assembler->add(r.gpr(), ra, rb);
                break;

            case llir::LoadStore::Op::VECTOR_LOAD:
                assert(extension == llir::Extension::NONE);
                assert(update == llir::MemOp::Update::NONE);
                assert(reg.zero_others);
                switch (reg.mask) {
                    case llir::Register::Mask::Vector128Full: ctx.assembler->lxvx(r.vsr(), ra, rb); break;
                    case llir::Register::Mask::Vector128High64: TODO(); break;
                    case llir::Register::Mask::Vector128Low64: TODO(); break;
                    case llir::Register::Mask::Vector128LowLow32: vsx_loadx_lowlow32(r.vsr(), ra, rb); break;

                    default:
                        ASSERT_NOT_REACHED();
                }

                break;

            case llir::LoadStore::Op::VECTOR_STORE:
                assert(extension == llir::Extension::NONE);
                assert(update == llir::MemOp::Update::NONE);
                switch (reg.mask) {
                    case llir::Register::Mask::Vector128Full: ctx.assembler->stxvx(r.vsr(), ra, rb); break;
                    case llir::Register::Mask::Vector128High64: TODO();
                    case llir::Register::Mask::Vector128Low64: TODO();
                    case llir::Register::Mask::Vector128LowLow32: vsx_storex_lowlow32(r.vsr(), ra, rb); break;

                    default:
                        ASSERT_NOT_REACHED();
                }

                break;

            default:
                ASSERT_NOT_REACHED();
        }
    };

#undef STORE_DISP
#undef STORE_INDEXED

    auto loadstore_disp_auto = [&](const AllocatedRegT &r, gpr_t ra, int64_t disp) {
        // If the operation uses post increment, use a displacement of 0 and add disp to ra afterwards.
        if (update == llir::MemOp::Update::POST) {
            loadstore_disp(r, ra, 0);
            if (!x86_64.disp_sign_from_df) {
                macro$alu$add_imm(ctx, ra, x86_64.disp);
            } else {
                assert(!vector);
                auto temp = ctx.reg_allocator().allocate_gpr();
                macro$load_imm(*ctx.assembler, temp.gpr(), disp, llir::Register::Mask::Full64, true);

                // Negate if DF is set
                ctx.assembler->bc(BO::FIELD_CLR, CR_MISCFLAGS_FIELD_DIRECTION, 2 * 4);
                ctx.assembler->neg(temp.gpr(), temp.gpr());
                ctx.assembler->add(ra, ra, temp.gpr());
            }
            return;
        }

        // Otherwise, use the provided displacement for the load/store
        assert(!x86_64.disp_sign_from_df); // Add support in the future if necessary

        // Different load/store instructions have varying displacement field widths, so whether
        // the provided disp will fit depends on the type of instruction that corresponds to the
        // provided size/extension.
        bool disp_fits;
        switch (op) {
            case llir::LoadStore::Op::LEA:
                disp_fits = assembler::fits_in_mask(disp, 0xFFFFU);
                break;

            case llir::LoadStore::Op::LOAD:
            case llir::LoadStore::Op::STORE:
                if (reg.mask == llir::Register::Mask::Full64)
                    disp_fits = assembler::fits_in_mask(disp, 0xFFFCU);
                else if (reg.mask == llir::Register::Mask::Low32 && extension == llir::Extension::SIGN)
                    disp_fits = assembler::fits_in_mask(disp, 0xFFFCU);
                else
                    disp_fits = assembler::fits_in_mask(disp, 0xFFFFU);
                break;

            case llir::LoadStore::Op::VECTOR_LOAD:
            case llir::LoadStore::Op::VECTOR_STORE:
                // Only certain VSX Loads/Stores support immediate displacements
                switch (reg.mask) {
                    case llir::Register::Mask::Vector128Full:
                        disp_fits = assembler::fits_in_mask(disp, 0xFFF0U);
                        break;

                    default:
                        disp_fits = false;
                }
                break;

            default:
                ASSERT_NOT_REACHED();
        }

        if (disp_fits) {
            if (tls_base_off) {
                // A segment register was selected, grab it from the runtime context and add it to ra
                assert(update == llir::MemOp::Update::NONE);
                auto temp = ctx.reg_allocator().allocate_gpr();
                ctx.assembler->ld(temp.gpr(), GPR_FIXED_RUNTIME_CTX, (int16_t)tls_base_off);
                ctx.assembler->add(temp.gpr(), temp.gpr(), ra);
                loadstore_disp(r, temp.gpr(), (int16_t)disp);
            } else {
                // Fits in an immediate displacement field
                loadstore_disp(r, ra, (int16_t)disp);
            }
        } else {
            // Need to disp load into a gpr before operation
            auto temp = ctx.reg_allocator().allocate_gpr();
            macro$load_imm(*ctx.assembler, temp.gpr(), disp, llir::Register::Mask::Full64, true);
            if (tls_base_off) {
                ctx.assembler->ld(temp.gpr(), GPR_FIXED_RUNTIME_CTX, (int16_t)tls_base_off);
                ctx.assembler->add(temp.gpr(), temp.gpr(), ra);
            }

            loadstore_indexed(r, ra, temp.gpr());
        }
    };


    AllocatedRegT *orig_base = nullptr;
    AllocatedRegT orig_base_storage, base, index;
    AllocatedRegT reg_fixed = register_allocator<TargetTraitsX86_64>::AllocatedRegT::from_host_register(reg);

    // Obtain GPRs for base and index if present
    if (x86_64.base.x86_64 != llir::X86_64Register::INVALID) {
        if (x86_64.base.x86_64 == llir::X86_64Register::RIP) {
            // Special case: RIP-relative addressing
            // Load the next instruction's address into a temporary GPR and use that as base
            base = ctx.reg_allocator().allocate_gpr();
            orig_base = &base;
            uint64_t next_rip = insn.address + insn.size;
            macro$load_imm(*ctx.assembler, base.gpr(), next_rip, llir::Register::Mask::Full64, true);
        } else if (x86_64.base.mask == llir::Register::Mask::Full64) {
            // Base is a 64-bit register that can be used directly
            base = ctx.reg_allocator().get_fixed_reg(x86_64.base);
            orig_base = &base;
        } else {
            // Base needs to be moved out of an aliased register into a temporary
            orig_base_storage = ctx.reg_allocator().get_fixed_reg(x86_64.base);
            orig_base = &orig_base_storage;
            base = ctx.reg_allocator().allocate_gpr();
            macro$move_register_masked(*ctx.assembler, base.gpr(), orig_base_storage.gpr(), x86_64.base.mask,
                                       llir::Register::Mask::Full64, true, false);
        }
    }

    if (x86_64.index.x86_64 != llir::X86_64Register::INVALID) {
        index = ctx.reg_allocator().get_fixed_reg(x86_64.index);
        // If index register is <64-bits OR has a scale, allocate a temporary and use that.
        if (x86_64.index.mask != llir::Register::Mask::Full64 || x86_64.scale != 1) {
            auto temp = ctx.reg_allocator().allocate_gpr();
            macro$move_register_masked(*ctx.assembler, temp.gpr(), index.gpr(), x86_64.index.mask,
                                       llir::Register::Mask::Full64, true, false, llir::Extension::SIGN);
            switch (x86_64.scale) {
                case 2:
                    ctx.assembler->sldi(temp.gpr(), index.gpr(), 1);
                    break;
                case 4:
                    ctx.assembler->sldi(temp.gpr(), index.gpr(), 2);
                    break;
                case 8:
                    ctx.assembler->sldi(temp.gpr(), index.gpr(), 3);
                    break;
            }

            index = std::move(temp);
        }
    }

    // Sanity checks
    if (update != llir::MemOp::Update::NONE) {
        // For loads/stores with update, only base should be present and disp should be non-zero
        assert(base);
        assert(!index);
        assert(x86_64.disp);
    }

    // Perform operation depending on available operands
    if (base && index) {
        // Both base and index registers are present
        if (!x86_64.disp) {
            // Optimization: If no displacement is present, used an indexed load/store
            loadstore_indexed(reg_fixed, base.gpr(), index.gpr());
        } else {
            // Store base+scaled_index in an intermediate reg and use a displacement load/store
            auto intermediate_reg = ctx.reg_allocator().allocate_gpr();
            ctx.assembler->add(intermediate_reg.gpr(), base.gpr(), index.gpr());

            loadstore_disp_auto(reg_fixed, intermediate_reg.gpr(), x86_64.disp);
        }
    } else if (base) {
        // Only base is present - use a displacement load/store
        loadstore_disp_auto(reg_fixed, base.gpr(), x86_64.disp);
    } else if (index) {
        // Only index is present - scale it and use a displacement load/store
        loadstore_disp_auto(reg_fixed, index.gpr(), x86_64.disp);
    } else {
        // Neither register is present, do a displacement load/store off of the immediate
        loadstore_disp_auto(reg_fixed, 0, x86_64.disp);
    }

    // If an update mode is specified, make sure it is written to the actual base register
    if (update != llir::MemOp::Update::NONE) {
        if (orig_base == &base)
            return; // Update already written

        macro$move_register_masked(*ctx.assembler, orig_base->gpr(), base.gpr(), llir::Register::Mask::Full64,
                                   x86_64.base.mask, x86_64.base.zero_others, false);
    }
}
