#pragma once

#include <util/util.h>
#include <elf_loader.h>
#include <mapped_file.h>
#include <disassembler.h>
#include <execution_context.h>
#include <codegen.h>
#include <virtual_address_mapper.h>
#include <arch/ppc64le/codegen/codegen_ppc64le.h>

#include <memory>
#include <variant>
#include <list>

namespace retrec {

class dynamic_recompiler {
    Architecture host;
    std::unique_ptr<execution_context> econtext;
    mapped_file binary;
    elf_loader loader;
    disassembler disasm;

    std::unique_ptr<codegen> gen;
    std::list<translated_code_region> translated_regions;
    virtual_address_mapper vam;

    //
    // Translation helpers
    //
    status_code translate_elf_function(const elf_loader::Symbol &symbol);
    status_code translate_raw_code_block(uint64_t vaddr);
    status_code translate_referenced_address(uint64_t address, uint64_t *resolved_out);
    status_code runtime_handle_untranslated_access();

public:
    dynamic_recompiler(Architecture host_, mapped_file binary_) :
        host(host_),
        econtext(std::make_unique<execution_context>()),
        binary(std::move(binary_)), loader(*econtext, binary),
        disasm(loader)
    {
    }

    //
    // Public functions
    //
    status_code init();
    status_code execute();
};

}

