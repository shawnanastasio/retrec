cmake_minimum_required(VERSION 3.17)
project(retrec)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

EXECUTE_PROCESS(COMMAND uname -m COMMAND tr -d '\n' OUTPUT_VARIABLE HOST_ARCH)
message(STATUS "Detected host arch: ${HOST_ARCH}")

#
# Flags
#
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "-fPIE -fno-exceptions -Wall -Wimplicit-fallthrough")
set(CMAKE_SOURCE_DIR "src")
# static
#SET(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
#SET(BUILD_SHARED_LIBS OFF)
#SET(CMAKE_EXE_LINKER_FLAGS "-static")

# Architecture-specific flags
if(${HOST_ARCH} STREQUAL "ppc64le")
    # Disable Altivec+VSX to reduce the number of instructions that have to be executed on
    # context save/restores. We don't do SIMD stuff, so this shouldn't affect anything else.
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mno-vsx -mno-altivec")
endif()

#
# Dependencies
#
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBELF REQUIRED IMPORTED_TARGET libelf)
pkg_check_modules(CAPSTONE REQUIRED IMPORTED_TARGET capstone)

# Main source directory
add_subdirectory(src)

