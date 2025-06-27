cmake_minimum_required(VERSION 3.12.0)

project(smss C)

file(GLOB SRC ${CMAKE_CURRENT_LIST_DIR}/*.c ${CMAKE_CURRENT_LIST_DIR}/${Arch}/*.c)

add_executable(smss ${SRC})
