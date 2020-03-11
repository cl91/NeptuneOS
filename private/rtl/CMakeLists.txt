cmake_minimum_required(VERSION 3.12.0)

project(rtl C)

# The runtime library.
file(GLOB SRC ${CMAKE_CURRENT_LIST_DIR}/src/*/*.c ${CMAKE_CURRENT_LIST_DIR}/src/*/${Arch}/*.c ${CMAKE_CURRENT_LIST_DIR}/src/*/${Arch}/*.s)
add_library(rtl STATIC ${SRC})
target_include_directories(
    rtl
    PUBLIC
        inc
	inc/${Arch}
	../../public/sdk/inc
    PRIVATE
        src/inc
	src/inc/${Arch}
)