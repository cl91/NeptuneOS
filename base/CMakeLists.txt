cmake_minimum_required(VERSION 3.12.0)

project(base)

include(../public/ndk/cmake/native.cmake)

add_subdirectory(smss)
add_subdirectory(ntcmd)
add_subdirectory(umtests)
