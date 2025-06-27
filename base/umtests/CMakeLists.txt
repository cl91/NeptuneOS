cmake_minimum_required(VERSION 3.12.0)

project(umtests C)

file(GLOB SRC ${CMAKE_CURRENT_LIST_DIR}/*.c)

add_executable(umtests ${SRC})
