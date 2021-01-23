cmake_minimum_required(VERSION 3.12)
project(O1C
        VERSION 1.0
        LANGUAGES C)

set(CMAKE_C_STANDARD 11)
add_compile_options(-O3 -Wall -Wextra)

add_subdirectory(src/main/c)
enable_testing()
add_subdirectory(src/test/c)
