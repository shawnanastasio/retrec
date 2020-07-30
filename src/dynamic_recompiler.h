#pragma once

#include <util.h>
#include <elf_loader.h>
#include <mapped_file.h>
#include <disassembler.h>
#include <execution_context.h>
#include <codegen.h>
#include <arch/ppc64le/codegen/codegen_ppc64le.h>

#include <memory>
#include <variant>

namespace retrec {

class dynamic_recompiler {
    Architecture host;
    std::unique_ptr<execution_context> econtext;
    mapped_file binary;
    elf_loader loader;
    disassembler disasm;

    std::unique_ptr<codegen> gen;

    std::variant<status_code, translated_code_region> translate_elf_function(const elf_loader::symbol &symbol);

public:
    dynamic_recompiler(Architecture host_, mapped_file binary_) :
        host(host_),
        econtext(std::make_unique<simple_execution_context>()),
        binary(std::move(binary_)), loader(*econtext, binary),
        disasm(loader)
    {
    }

    status_code init();
    status_code execute();
};

}

