#include <dynamic_recompiler.h>
#include <platform/syscall_emulation.h>


using namespace retrec;

status_code dynamic_recompiler::init() {
    auto ret = econtext->init();
    if (ret != status_code::SUCCESS)
        return ret;

    ret = loader.init();
    if (ret != status_code::SUCCESS)
        return ret;

    ret = loader.load_all();
    if (ret != status_code::SUCCESS)
        return ret;

    ret = disasm.init();
    if (ret != status_code::SUCCESS)
        return ret;

    // We have to wait until here to initialize the codegen with
    // the correct architecture detected by the elf loader.
    switch (host) {
        case Architecture::ppc64le:
            gen = std::make_unique<codegen_ppc64le<ppc64le::target_traits_x86_64>>(loader.target_arch(), *econtext);
            break;
        default:
            TODO();
    }

    ret = gen->init();
    if (ret != status_code::SUCCESS)
        return ret;

    init_syscall_emulator<syscall_emulator>(loader.target_arch());

    return status_code::SUCCESS;
}

status_code dynamic_recompiler::execute() {
    /**
     * Translate entrypoint
     * Jump to entrypoint
     */

    // Lookup entrypoint's symbol
    auto *entry_symbol = loader.lookup(loader.entrypoint(), loader.text_section_index());
    if (!entry_symbol) {
        pr_error("Failed to find entrypoint symbol!\n");
        return status_code::BADELF;
    }

    // Translate function
    auto code_op = translate_elf_function(*entry_symbol);
    if (std::holds_alternative<status_code>(code_op))
        return std::get<status_code>(code_op);
    auto code = std::get<translated_code_region>(code_op);

    // Enter the code!
    pr_info("entering code at %p, len: %zu\n", code.code(), code.size());
    auto ret = econtext->initialize_runtime_context(loader.target_arch(), &code);
    if (ret != status_code::SUCCESS) {
        pr_error("Failed to initialize runtime context for translated code!\n");
        return ret;
    }
    econtext->enter_translated_code();

    return status_code::SUCCESS;
}

std::variant<status_code, translated_code_region> dynamic_recompiler::translate_elf_function(const elf_loader::symbol &symbol) {
    // Determine length of entrypoint routine
    uint64_t entry_len = loader.get_symbol_size(symbol);
    pr_debug("entrypoint length: %zu\n", entry_len);
    const void *entry_data_ptr = loader.get_symbol_data_ptr(symbol);
    if (!entry_data_ptr) {
        pr_error("Failed to get symbol data ptr!\n");
        return status_code::NOMEM;
    }

    // Disassemble
    std::vector<llir::Insn> lifted_insns;
    if (disasm.disassemble_region(entry_data_ptr, entry_len, symbol.value, lifted_insns) != status_code::SUCCESS) {
        pr_error("Failed to disassemble region!\n");
        return status_code::BADELF;
    }

    lifted_llir_block block(std::move(lifted_insns), lifted_llir_block::Flags::FULL_FUNCTION);

    // Translate the routine
    std::optional<translated_code_region> translated_code;
    auto ret = gen->translate(block, translated_code);
    if (ret != status_code::SUCCESS) {
        pr_error("Failed to translate routine!\n");
        return ret;
    }

    return *translated_code;
}
