set(ROOT ${PROJECT_SOURCE_DIR})

# Clone capstone if necesssry
if(NOT EXISTS "${ROOT}/external/capstone/CMakeLists.txt")
    message(STATUS "Cloning capstone git")
    execute_process(COMMAND git submodule update --init -- external/capstone WORKING_DIRECTORY "${ROOT}")
endif()

# For Release/ReleaseDebug, enable DIET mode for a large performance boost
if(CMAKE_BUILD_TYPE MATCHES "Release")
    set(CAPSTONE_BUILD_DIET ON CACHE BOOL "")
else()
    set(CAPSTONE_BUILD_DIET OFF CACHE BOOL "")
endif()

set(CAPSTONE_BUILD_STATIC ON CACHE BOOL "")
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "")
set(CAPSTONE_INSTALL OFF CACHE BOOL "")
set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "")
set(CAPSTONE_X86_SUPPORT ON CACHE BOOL "")

set(CMAKE_BUILD_TYPE_OLD ${CMAKE_BUILD_TYPE})
set(CMAKE_BUILD_TYPE Release)
add_subdirectory(external/capstone "${ROOT}/capstone" EXCLUDE_FROM_ALL)
set(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE_OLD})

set(CapstoneGit_INCLUDE "${ROOT}/external/capstone/include")
set(CapstoneGit_LIBS capstone-static)
