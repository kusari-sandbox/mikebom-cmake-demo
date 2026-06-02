# mikebom-cmake-demo — minimal cmake project demonstrating mikebom's
# source-tree + binary scanning against a cmake C/C++ project.
#
# What this exercises:
#   - mikebom's cmake source-tree reader (milestone 103): picks up
#     the FetchContent_Declare(zlib ...) line and emits a
#     pkg:github/madler/zlib@v1.3.1 component in the source-tier SBOM.
#   - mikebom's binary analysis (milestones 023-099 + 108): scans
#     the compiled `crc-demo` executable + statically-embedded zlib
#     for linkage signals + symbol fingerprints.
#
# FetchContent + a static link of zlib means the resulting binary
# contains zlib's exported symbols in its dynamic symbol table —
# `mikebom sbom scan --fingerprints-corpus` matches them against
# the external corpus and stamps `mikebom:fingerprint-corpus-sha`.

cmake_minimum_required(VERSION 3.16)

project(crc-demo
    LANGUAGES C
    VERSION 0.1.0
    DESCRIPTION "Tiny zlib-using C program for the mikebom cmake demo"
)

include(FetchContent)

# Pinned upstream zlib release. cmake reader emits
# pkg:github/madler/zlib@v1.3.1 from this declaration.
FetchContent_Declare(
    zlib
    GIT_REPOSITORY https://github.com/madler/zlib.git
    GIT_TAG v1.3.1
)

# Keep zlib's own tests / examples out of OUR build.
set(ZLIB_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(zlib)

add_executable(crc-demo src/main.c)

# Static link so the binary embeds zlib's symbols (vs dynamic-link
# to a system libz). Both targets are exposed by zlib's own
# CMakeLists.txt as of v1.3.1.
target_link_libraries(crc-demo PRIVATE zlibstatic)

# ENABLE_EXPORTS adds `-rdynamic` on ELF targets (Linux) and is a
# no-op on Mach-O / PE. This surfaces zlib's symbols in the binary's
# dynamic-symbol table so mikebom's symbol-fingerprint matcher can
# identify the statically-embedded library. Without this, gcc / clang
# would strip the unused symbols from `.dynsym` (correct optimization
# for binaries that don't expose their internals to plugins) and the
# matcher would have nothing to fingerprint.
#
# Real-world parallel: any C/C++ binary that loads plugins via
# dlopen() typically uses ENABLE_EXPORTS / -rdynamic so plugin code
# can call back into the host. Those binaries are exactly the class
# that mikebom's fingerprint matcher targets.
set_target_properties(crc-demo PROPERTIES ENABLE_EXPORTS TRUE)
target_include_directories(crc-demo PRIVATE
    ${zlib_SOURCE_DIR}
    ${zlib_BINARY_DIR}
)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(crc-demo PRIVATE -Wall -Wextra -Wpedantic)
endif()
