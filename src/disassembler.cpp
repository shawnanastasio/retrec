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

            lifter = std::make_unique<llir_lifter_x86_64>(capstone_handle);
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
                                             std::vector<llir::Insn> &llir_out) {
    cs_insn *insns_tmp;
    size_t count = cs_disasm(capstone_handle, (const uint8_t *)code, max_length, ip, 0, &insns_tmp);
    unique_cs_insn_arr insns(insns_tmp, cs_insn_deleter(count));

    std::vector<llir::Insn> llir_insns;

    for (size_t i=0; i<count; i++) {
        cs_insn *cur = &insns[i];
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

        pr_debug("LLIR: %s\n", llir::to_string(*(llir_insns.end() - 1)).c_str());
    }

    llir_out = std::move(llir_insns);
    return status_code::SUCCESS;
}
