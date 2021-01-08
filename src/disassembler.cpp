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

#include <disassembler.h>
#include <arch/x86_64/llir/llir_lifter_x86_64.h>

#include <cassert>
#include <vector>

using namespace retrec;

template <typename T>
std::string array_to_string(T arr[], size_t len) {
    std::string ret = "{";
    if (len) {
        for (size_t i = 0; i < len - 1; i++) {
            ret += std::to_string(arr[i]) + ", ";
        }
        ret += std::to_string(arr[len - 1]) + "}";
    } else {
        ret += "}";
    }
    return ret;
};

template <>
std::string array_to_string(cs_x86_op arr[], size_t len) {
    std::string ret = "{";
    if (len) {
        for (size_t i = 0; i < len - 1; i++) {
            ret += std::to_string(arr[i].type) + ", ";
        }
        ret += std::to_string(arr[len - 1].type) + "}";
    } else {
        ret += "}";
    }
    return ret;
};

disassembler::~disassembler() {
    if (init_done)
        cs_close(&capstone_handle);
}

status_code disassembler::init() {
    cs_arch capstone_arch;
    cs_mode capstone_mode;
    switch(loader.target_arch()) {
        case Architecture::X86_64:
            capstone_arch = CS_ARCH_X86;
            capstone_mode = CS_MODE_64;

            if (cs_open(capstone_arch, capstone_mode, &capstone_handle) != CS_ERR_OK)
                return status_code::NOMEM;

            lifter = std::make_unique<llir_lifter_x86_64>();
            break;

        default:
            pr_error("Unsupported architecture %d!\n", (int)arch);
            return status_code::BADARCH;
    }

    cs_option(capstone_handle, CS_OPT_DETAIL, CS_OPT_ON);

    init_done = true;
    return status_code::SUCCESS;
}

status_code disassembler::disassemble_region(const void *code, size_t max_length, uint64_t ip,
                                             std::vector<llir::Insn> &llir_out, Mode mode) {
    cs_insn *cur = cs_malloc(capstone_handle);
    unique_cs_insn_arr insns(cur, cs_insn_deleter(1));
    std::vector<llir::Insn> llir_insns;

    while (cs_disasm_iter(capstone_handle, (const uint8_t **)&code, &max_length, &ip, cur)) {
        cs_detail *detail = cur->detail;
        assert(detail);

        pr_debug("0x%zx: %s %s, operands: %s, groups: %s\n", cur->address, cur->mnemonic, cur->op_str,
                array_to_string(detail->x86.operands, detail->x86.op_count).c_str(),
                array_to_string(detail->groups, detail->groups_count).c_str());

        // Lift to LLIR
        status_code res = lifter->lift(cur, llir_insns);
        if (res != status_code::SUCCESS) {
            pr_error("Failed to lift instruction!\n");
            return res;
        }

        if (mode == Mode::PARTIAL) {
            // In partial mode, we need to stop whenever a branch is encountered
            auto last_insn = llir_insns.end() - 1;
            if (last_insn->iclass() == llir::Insn::Class::BRANCH)
                break;
        }

        pr_debug("LLIR: %s\n", llir::to_string(*(llir_insns.end() - 1)).c_str());
    }

    llir_out = std::move(llir_insns);
    return status_code::SUCCESS;
}
