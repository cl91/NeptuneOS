cmake_minimum_required(VERSION 3.12.0)

include(../public/ndk/cmake/native.cmake)

project(base)

add_subdirectory(sm)
add_subdirectory(ntcmd)
add_subdirectory(umtests)
