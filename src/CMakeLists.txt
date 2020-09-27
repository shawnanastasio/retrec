# Cleaner file name macro for use in logging
# https://stackoverflow.com/a/16658858
string(LENGTH "${CMAKE_SOURCE_DIR}/" SOURCE_PATH_SIZE)
add_definitions("-DSOURCE_PATH_SIZE=${SOURCE_PATH_SIZE}")

#
# Target
#
add_executable(retrec
    main.cpp
    mapped_file.cpp
    mapped_file.h
    dynamic_recompiler.cpp
    dynamic_recompiler.h
    elf_loader.cpp
    elf_loader.h
    util.h
    util.cpp
    execution_context.cpp
    execution_context.h
    disassembler.cpp
    disassembler.h
    llir.h
    arch/x86_64/llir/llir_lifter_x86_64.cpp
    arch/x86_64/llir/llir_lifter_x86_64.h
    arch/x86_64/llir/llir_registers_x86_64.h
    arch/x86_64/llir/llir_operands_x86_64.h
    codegen.h
    arch/ppc64le/codegen/codegen_ppc64le.cpp
    arch/ppc64le/codegen/codegen_ppc64le.h
    arch/ppc64le/codegen/assembler.cpp
    arch/ppc64le/codegen/assembler.h
    arch/ppc64le/codegen/register_allocator.h
    arch/ppc64le/codegen/register_allocator.cpp
    arch/x86_64/cpu_context_x86_64.h
    process_memory_map.cpp
    process_memory_map.h
    allocators.cpp
    allocators.h
    arch/ppc64le/codegen/thunks.cpp
    arch/ppc64le/cpu_context_ppc64le.h
    arch/ppc64le/llir/llir_registers_ppc64le.h
    arch/arch.h
    arch/ppc64le/runtime_context_ppc64le.h
    arch/ppc64le/runtime_context_ppc64le.cpp
    arch/x86_64/syscalls.h
    arch/ppc64le/syscalls.h
    platform/syscall_emulation.cpp
    platform/syscall_emulation.h
    platform/generic_syscalls.h)

target_link_libraries(retrec PUBLIC ${LIBELF_LIBRARIES} ${CAPSTONE_LIBRARIES})
target_include_directories(retrec PUBLIC ${LIBELF_INCLUDE_DIRS} ${CAPSTONE_INCLUDE_DIRS})
target_include_directories(retrec PRIVATE .)

