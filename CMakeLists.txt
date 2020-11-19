cmake_minimum_required(VERSION 3.17)
project(retrec)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

EXECUTE_PROCESS(COMMAND uname -m COMMAND tr -d '\n' OUTPUT_VARIABLE HOST_ARCH)
message(STATUS "Detected host arch: ${HOST_ARCH}")

#
# User configurable options
#
option(MIN_LOG_LEVEL "MIN_LOG_LEVEL" "-1")
if(NOT ${MIN_LOG_LEVEL})
    if (CMAKE_BUILD_TYPE MATCHES "Debug")
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
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIE -fno-exceptions -Wall -Wimplicit-fallthrough -Wconversion -Wextra -Werror=conversion -Wno-sign-conversion")
set(CMAKE_SOURCE_DIR "src")

# Architecture-specific flags
if(${HOST_ARCH} STREQUAL "ppc64le")
    # ppc64le specific options
endif()

#
# Dependencies
#
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBELF REQUIRED IMPORTED_TARGET libelf)
pkg_check_modules(CAPSTONE REQUIRED IMPORTED_TARGET capstone)

# Main source directory
add_subdirectory(src)

