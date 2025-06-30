cmake_minimum_required(VERSION 3.12.0)

project(psxss)

include(../../public/ndk/cmake/native.cmake)

include_directories(
    inc
    ../../public/posix/inc
)

file(GLOB SRC src/*.c)

add_executable(psxss ${SRC})

