cmake_minimum_required(VERSION 3.7.2)

project(ntcmd C)

file(GLOB SRC ${CMAKE_CURRENT_LIST_DIR}/*.c)

add_executable(ntcmd ${SRC})
