cmake_minimum_required(VERSION 3.12.0)

project(base)

link_directories(${NDK_LIB_PATH})

add_subdirectory(server)
add_subdirectory(client)