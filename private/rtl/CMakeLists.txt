#
# Copyright 2019, Data61
# Commonwealth Scientific and Industrial Research Organisation (CSIRO)
# ABN 41 687 119 230.
#
# This software may be distributed and modified according to the terms of
# the BSD 2-Clause license. Note that NO WARRANTY is provided.
# See "LICENSE_BSD2.txt" for details.
#
# @TAG(DATA61_BSD)
#
# Compile CRT for given arch and get crt0.o, crti.o, and crtn.o.
# Add crt0.o and crti.o to the start of all targets link flags.
# Add crtn.o to the end of all targets link flags.

# Compile runtime library from src.
# Use src as private includes for crt and runtime library routines.
# Use include as public includes for crt and runtime library routines.

cmake_minimum_required(VERSION 3.12.0)

project(rtl C)

# The runtime library.
file(GLOB SRC ${CMAKE_CURRENT_LIST_DIR}/src/*/*.c ${CMAKE_CURRENT_LIST_DIR}/src/*/${Arch}/*.c)
add_library(rtl STATIC ${SRC})
target_include_directories(
    rtl
    PUBLIC
        inc
	inc/${Arch}
)

target_link_libraries(rtl PUBLIC sel4 sel4_autoconf)
