# Common runtime library linked by both ntos and ntdll

cmake_minimum_required(VERSION 3.12.0)

project(rtl C)

file(GLOB SRC ${CMAKE_CURRENT_LIST_DIR}/src/*/*/*.c ${CMAKE_CURRENT_LIST_DIR}/src/*/*/${Arch}/*.c ${CMAKE_CURRENT_LIST_DIR}/src/*/*/${Arch}/*.S)
add_library(rtl STATIC ${SRC})
target_include_directories(
    rtl
    PUBLIC
	../../public/sdk/inc
	../../public/crt/inc
	../../public/crt/inc/${Arch}
	inc
	inc/${Arch}
    PRIVATE
	src/inc
	src/inc/${Arch}
)
