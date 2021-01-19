cmake_minimum_required(VERSION 3.17)
project(O1C
        VERSION 1.0
        LANGUAGES C)

include(FetchContent)

set(CMAKE_C_STANDARD 11)
# todo: more warnings enabled
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -Wall -Wextra -Wstrict-prototypes -Wno-error=strict-prototypes -fvisibility=hidden")

add_subdirectory(src)
enable_testing()
add_subdirectory(test)
