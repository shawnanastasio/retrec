#pragma once

#include <elf_loader.h>
#include <llir.h>

#include <memory>
#include <vector>

#include <capstone/capstone.h>

namespace retrec {

//
// Unique Pointer for cs_insn array
//
struct cs_insn_deleter {
    size_t count;
    cs_insn_deleter(size_t count_) : count(count_) {}
    void operator()(cs_insn *insn) { cs_free(insn, count); }
};
using unique_cs_insn_arr = std::unique_ptr<cs_insn[], cs_insn_deleter>;

class llir_lifter {
public:
    virtual status_code lift(cs_insn *insn, std::vector<llir::Insn> &out) = 0;
};

class disassembler {
    elf_loader &loader;

    bool init_done = false;
    Architecture arch;
    csh capstone_handle;
    std::unique_ptr<llir_lifter> lifter;
public:
    DISABLE_COPY_AND_MOVE(disassembler)
    explicit disassembler(elf_loader &loader_) :
        loader(loader_) {}
    ~disassembler();

    status_code init();
    status_code disassemble_region(const void *code, size_t max_length, uint64_t ip,
                                   std::vector<llir::Insn> &llir_out);
};

}

