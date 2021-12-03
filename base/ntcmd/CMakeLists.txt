cmake_minimum_required(VERSION 3.7.2)

project(ntcmd C)

file(GLOB SRC ${CMAKE_CURRENT_LIST_DIR}/src/*.c)

add_executable(ntcmd ${SRC})

target_include_directories(ntcmd PRIVATE inc)
