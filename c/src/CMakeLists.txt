include(TestBigEndian)
include(CheckSymbolExists)
include(GenerateExportHeader)
include(FetchContent)

set(O1C_SOURCE_FILES crypto.c auth.c aead.c sha512.c drbg.c util.c curve25519.c hash.c jni.c)

FetchContent_Declare(blake3
        GIT_REPOSITORY https://github.com/BLAKE3-team/BLAKE3.git
        GIT_TAG 35aa4259bd37457f15d5070957da4825bf64c838 # tag 0.3.7
        )
FetchContent_GetProperties(blake3)
if (NOT blake3_POPULATED)
    FetchContent_Populate(blake3)
endif ()

set(BLAKE3_SOURCE_FILES
        ${blake3_SOURCE_DIR}/c/blake3.c
        ${blake3_SOURCE_DIR}/c/blake3_dispatch.c
        ${blake3_SOURCE_DIR}/c/blake3_portable.c)
set(BLAKE3_ASM_UNIX_FILES
        ${blake3_SOURCE_DIR}/c/blake3_avx2_x86-64_unix.S
        ${blake3_SOURCE_DIR}/c/blake3_avx512_x86-64_unix.S
        ${blake3_SOURCE_DIR}/c/blake3_sse41_x86-64_unix.S
        ${blake3_SOURCE_DIR}/c/blake3_sse2_x86-64_unix.S)
# TODO: mscv and mingw asm options
add_library(blake3_sse2 OBJECT ${blake3_SOURCE_DIR}/c/blake3_sse2.c)
target_compile_options(blake3_sse2 PUBLIC -msse2)
add_library(blake3_sse41 OBJECT ${blake3_SOURCE_DIR}/c/blake3_sse41.c)
target_compile_options(blake3_sse41 PUBLIC -msse4.1)
add_library(blake3_avx2 OBJECT ${blake3_SOURCE_DIR}/c/blake3_avx2.c)
target_compile_options(blake3_avx2 PUBLIC -mavx2)
add_library(blake3_avx512 OBJECT ${blake3_SOURCE_DIR}/c/blake3_avx512.c)
target_compile_options(blake3_avx512 PUBLIC -mavx512f -mavx512vl)

add_library(o1c SHARED ${O1C_SOURCE_FILES}
        ${BLAKE3_SOURCE_FILES} ${BLAKE3_ASM_UNIX_FILES}
        $<TARGET_OBJECTS:blake3_sse2> $<TARGET_OBJECTS:blake3_sse41>
        $<TARGET_OBJECTS:blake3_avx2> $<TARGET_OBJECTS:blake3_avx512>)
generate_export_header(o1c)
target_include_directories(o1c PUBLIC ../include ${blake3_SOURCE_DIR}/c ${PROJECT_BINARY_DIR}/src)
target_include_directories(o1c PRIVATE include)
target_compile_options(o1c PRIVATE
        -pedantic -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wstrict-prototypes -Wno-error=strict-prototypes -fvisibility=hidden)

find_package(JNI REQUIRED)
target_include_directories(o1c PUBLIC ${JNI_INCLUDE_DIRS})
#target_link_libraries(o1c PUBLIC ${JNI_LIBRARIES})
# TODO: https://cmake.org/cmake/help/latest/module/UseJava.html
#find_package(Java 1.8 REQUIRED COMPONENTS Development)

# compiler definitions
test_big_endian(NATIVE_BIG_ENDIAN)
if (${NATIVE_BIG_ENDIAN})
    add_compile_definitions(o1c PUBLIC NATIVE_BIG_ENDIAN)
else ()
    add_compile_definitions(o1c PUBLIC NATIVE_LITTLE_ENDIAN)
endif ()

if (${CMAKE_SYSTEM_PROCESSOR} MATCHES "64")
    add_compile_definitions(o1c PUBLIC ARCH_WORD_BITS=64)
else ()
    add_compile_definitions(o1c PUBLIC ARCH_WORD_BITS=32)
endif ()

check_symbol_exists(memset_s string.h HAVE_MEMSET_S)
if (${HAVE_MEMSET_S})
    add_compile_definitions(o1c PUBLIC HAVE_MEMSET_S)
endif ()
