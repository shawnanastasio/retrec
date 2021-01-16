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

#pragma once

#include <util/util.h>
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

    uint64_t text_shndx { 0 };
    uint64_t base_load_address { 0 };
    GElf_Shdr text_shdr;
public:
    DISABLE_COPY_AND_MOVE(elf_loader)
    elf_loader(execution_context &econtext_, mapped_file &file_) :
        econtext(econtext_), file(file_) {}
    ~elf_loader();

    status_code init();
    status_code load_all();

    struct Symbol {
        std::string name;
        uint8_t info;
        uint8_t other;
        uint64_t shndx;
        uint64_t value;
        uint64_t size;
        enum class Bind {
            LOCAL = 0,
            GLOBAL = 1,
            WEAK = 2,
            NUM = 3,
            GNU_UNIQUE = 10,

            _ANY = 255
        } bind;
    };

    enum class LookupPolicy {
        EXACT,    // Exact matches only
        CONTAINS, // addr is within symbol start + size
    };

    [[nodiscard]] const Symbol *lookup(uint64_t addr, uint64_t shndx, Symbol::Bind bind, LookupPolicy policy) const;
    [[nodiscard]] uint64_t get_symbol_size(const Symbol &sym) const;
    const void *get_symbol_data_ptr(const elf_loader::Symbol &sym);

    Architecture target_arch() const { return arch; }
    uint64_t entrypoint() const { return ehdr.e_entry; }
    const std::vector<Symbol> &symbol_table() const { return symbols; }
    uint64_t text_section_index() const { return text_shndx; }
    const auto &get_ehdr() const { return ehdr; }
    auto get_base_address() const { return base_load_address; }

private:
    std::vector<Symbol> symbols;
};

}
