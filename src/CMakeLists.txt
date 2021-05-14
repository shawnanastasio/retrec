# Cleaner file name macro for use in logging
# https://stackoverflow.com/a/16658858
string(LENGTH "${CMAKE_SOURCE_DIR}/" SOURCE_PATH_SIZE)
add_definitions("-DSOURCE_PATH_SIZE=${SOURCE_PATH_SIZE}")

#
# Common source files
#
set(RETREC_SOURCES
    allocators.cpp
    allocators.h
    arch/arch.h
    arch/definitions.h
    arch/generic/runtime_context_generic.cpp
    arch/generic/runtime_context_generic.h
    arch/ppc64le/codegen/abi.h
    arch/ppc64le/codegen/assembler.h
    arch/ppc64le/codegen/codegen_ppc64le.h
    arch/ppc64le/codegen/codegen_ppc64le_internal.h
    arch/ppc64le/codegen/codegen_types.h
    arch/ppc64le/codegen/register_allocator.h
    arch/ppc64le/cpu_context_ppc64le.h
    arch/ppc64le/llir/llir_registers_ppc64le.h
    arch/ppc64le/runtime_context_ppc64le.h
    arch/ppc64le/syscalls.h
    arch/runtime_context_dispatcher.cpp
    arch/runtime_context_dispatcher.h
    arch/target_environment.h
    arch/x86_64/cpu_context_x86_64.h
    arch/x86_64/llir/llir_lifter_x86_64.cpp
    arch/x86_64/llir/llir_lifter_x86_64.h
    arch/x86_64/llir/llir_operands_x86_64.h
    arch/x86_64/llir/llir_registers_x86_64.h
    arch/x86_64/syscalls.h
    arch/x86_64/target_environment.cpp
    arch/x86_64/target_environment.h
    codegen.h
    disassembler.cpp
    disassembler.h
    dynamic_recompiler.cpp
    dynamic_recompiler.h
    elf_loader.cpp
    elf_loader.h
    execution_context.cpp
    execution_context.h
    instruction_stream.h
    llir.h
    main.cpp
    mapped_file.cpp
    mapped_file.h
    platform/generic_syscalls.cpp
    platform/generic_syscalls.h
    platform/syscall_emulator.cpp
    platform/syscall_emulator.h
    platform/syscall_types.h
    process_memory_map.cpp
    process_memory_map.h
    util/magic.h
    util/staticvector.h
    util/util.cpp
    util/util.h
    virtual_address_mapper.cpp
    virtual_address_mapper.h
)

#
# Architecture-dependant source files
#
if(HOST_ARCH MATCHES "ppc64")
    set(RETREC_SOURCES ${RETREC_SOURCES}
        arch/ppc64le/codegen/assembler.cpp
        arch/ppc64le/codegen/codegen_fixed_helpers.cpp
        arch/ppc64le/codegen/codegen_ppc64le.cpp
        arch/ppc64le/codegen/codegen_target_x86_64.cpp
        arch/ppc64le/codegen/codegen_types.cpp
        arch/ppc64le/codegen/register_allocator.cpp
        arch/ppc64le/runtime_context_ppc64le.cpp
        arch/ppc64le/syscalls.cpp
    )
endif()

add_executable(retrec ${RETREC_SOURCES})

target_link_libraries(retrec PUBLIC ${LIBELF_LIBRARIES} ${CapstoneGit_LIBS})
target_include_directories(retrec PUBLIC ${LIBELF_INCLUDE_DIRS} ${CapstoneGit_INCLUDE})

target_include_directories(retrec PRIVATE .)

