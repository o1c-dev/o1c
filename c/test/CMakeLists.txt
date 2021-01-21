link_libraries(o1c)
include_directories(../src/include)
include_directories(../include)

# use libsodium for validating some algorithm compatibility
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM IMPORTED_TARGET libsodium)
if (SODIUM_FOUND)
    link_libraries(PkgConfig::SODIUM)
else()
    include(ExternalProject)
    find_program(MAKE_EXE NAMES gmake nmake make)
    ExternalProject_Add(sodium
            URL https://github.com/jedisct1/libsodium/releases/download/1.0.18-RELEASE/libsodium-1.0.18.tar.gz
            URL_HASH SHA256=6f504490b342a4f8a4c4a02fc9b866cbef8622d5df4e5452b46be121e46636c1
            UPDATE_COMMAND ""
            BUILD_IN_SOURCE 1
            CONFIGURE_COMMAND ./configure
            BUILD_COMMAND ${MAKE_EXE}
            INSTALL_COMMAND ${MAKE_EXE} install)
    add_library(libsodium STATIC IMPORTED GLOBAL)
    link_libraries(libsodium)
endif ()


# tests
# TODO: find and use a real unit test framework

add_executable(test_chacha20 test_chacha20.c)
add_test(NAME ChaCha20 COMMAND test_chacha20)

add_executable(test_curve25519 test_curve25519.c)
add_test(NAME X25519 COMMAND test_curve25519)

add_executable(test_poly1305 test_poly1305.c)
add_test(NAME Poly1305 COMMAND test_poly1305)

add_executable(test_chacha20poly1305 test_chacha20poly1305.c)
add_test(NAME XChaCha20Poly1305 COMMAND test_chacha20poly1305)

add_executable(test_ed25519 test_ed25519.c)
add_test(NAME Ed25519 COMMAND test_ed25519)

add_executable(test_ristretto255 test_ristretto255.c)
add_test(NAME Ristretto255 COMMAND test_ristretto255)
