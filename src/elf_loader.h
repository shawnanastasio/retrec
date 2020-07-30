#pragma once

#include <util.h>
#include <mapped_file.h>
#include <execution_context.h>

#include <string>
#include <vector>
#include <cstdint>

#include <libelf.h>
#include <gelf.h>

namespace retrec {

class elf_loader {
    execution_context &econtext;
    mapped_file &file;
    Elf *elf = nullptr;
    GElf_Ehdr ehdr;
    Architecture arch;

    uint64_t text_shndx;
    GElf_Shdr text_shdr;
public:
    DISABLE_COPY_AND_MOVE(elf_loader)
    elf_loader(execution_context &econtext_, mapped_file &file_) :
        econtext(econtext_), file(file_) {}
    ~elf_loader();

    status_code init();
    status_code load_all();

    struct symbol {
        std::string name;
        uint8_t info;
        uint8_t other;
        uint64_t shndx;
        uint64_t value;
        uint64_t size;
    };

    [[nodiscard]] const symbol *lookup(uint64_t addr, uint64_t shndx) const;
    [[nodiscard]] uint64_t get_symbol_size(const symbol &sym) const;
    const void *get_symbol_data_ptr(const elf_loader::symbol &sym);

    [[nodiscard]] Architecture target_arch() const { return arch; }
    [[nodiscard]] uint64_t entrypoint() const { return ehdr.e_entry; }
    [[nodiscard]] const std::vector<symbol> &symbol_table() const { return symbols; }
    [[nodiscard]] uint64_t text_section_index() const { return text_shndx; }


private:
    std::vector<symbol> symbols;
};

}
