cmake_minimum_required(VERSION 3.10)
project(retrec)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

EXECUTE_PROCESS(COMMAND uname -m COMMAND tr -d '\n' OUTPUT_VARIABLE HOST_ARCH)
message(STATUS "Detected host arch: ${HOST_ARCH}")

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(RETREC_DEBUG_BUILD 0)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(RETREC_DEBUG_BUILD 1)
endif()

# Compile external dependencies
include(external/external.cmake)

#
# User configurable options
#
set(MIN_LOG_LEVEL AUTO CACHE STRING "Set minimum log level {AUTO, 0, 1, 2, 3}")
set_property(CACHE MIN_LOG_LEVEL PROPERTY STRINGS "AUTO" "0" "1" "2" "3")
if(${MIN_LOG_LEVEL} MATCHES "AUTO")
    if (CMAKE_BUILD_TYPE STREQUAL "Debug")
        # Set min log level to lowest for debug builds
        set(MIN_LOG_LEVEL 0)
    else()
        # Otherwise set it to WARN
        set(MIN_LOG_LEVEL 2)
    endif()
endif()
message(STATUS "Minimum log level is: ${MIN_LOG_LEVEL}") # Set with 'cmake -DMIN_LOG_LEVEL=<0,1,2,3>'
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DRETREC_MINIMUM_LOG_LEVEL=${MIN_LOG_LEVEL}")

#
# Compiler flags
#
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIE -fno-exceptions -Wall -Wimplicit-fallthrough -Wextra -Wpessimizing-move -Wno-psabi")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DRETREC_DEBUG_BUILD=${RETREC_DEBUG_BUILD}")
set(CMAKE_SOURCE_DIR "src")

message(STATUS "Build type is: ${CMAKE_BUILD_TYPE}")
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Og -g -Werror=switch")
elseif (CMAKE_BUILD_TYPE STREQUAL "ReleaseDebug")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -mcpu=power9 -g -DNDEBUG -Wno-unused-variable -Wno-unused-parameter")
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -Wno-unused-variable -Wno-unused-parameter")
else()
    message(FATAL_ERROR "Unknown CMAKE_BUILD_TYPE: Choices are 'Release', 'ReleaseDebug', 'Debug'")
endif()

# Compiler-specific flags
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    if(NOT CMAKE_CXX_COMPILER_VERSION VERSION_LESS 10.0)
        # GCC >=10 has non-broken -Wconversion, so we can enable it
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wconversion -Wno-sign-conversion")
    endif()
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wconversion -Wno-sign-conversion")
endif()

# Architecture-specific flags
if(${HOST_ARCH} STREQUAL "ppc64le")
    # ppc64le specific options
endif()

#
# Dependencies
#
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBELF REQUIRED IMPORTED_TARGET libelf)

# Main source directory
add_subdirectory(src)

