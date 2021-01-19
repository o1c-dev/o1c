link_libraries(o1c)
include_directories(../src/include)
include_directories(../include)

# use libsodium for validating some algorithm compatibility
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
link_libraries(PkgConfig::SODIUM)

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
