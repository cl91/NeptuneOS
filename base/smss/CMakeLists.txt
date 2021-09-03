cmake_minimum_required(VERSION 3.7.2)

project(smss C)

file(GLOB SRC ${CMAKE_CURRENT_LIST_DIR}/src/*.c ${CMAKE_CURRENT_LIST_DIR}/src/${Arch}/*.c)

add_executable(smss ${SRC})
