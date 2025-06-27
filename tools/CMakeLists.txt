cmake_minimum_required(VERSION 3.12.0)

project(tools)

add_compile_options(-Wall)

add_subdirectory(spec2def)
add_subdirectory(geninc)
add_subdirectory(utf16le)
