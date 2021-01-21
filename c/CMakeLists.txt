cmake_minimum_required(VERSION 3.12)
project(O1C
        VERSION 1.0
        LANGUAGES C)

include(FetchContent)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -Wall -Wextra -pedantic -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wstrict-prototypes -Wno-error=strict-prototypes -fvisibility=hidden")

add_subdirectory(src)
enable_testing()
add_subdirectory(test)
