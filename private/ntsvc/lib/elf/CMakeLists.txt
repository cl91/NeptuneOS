#
# Copyright 2017, Data61
# Commonwealth Scientific and Industrial Research Organisation (CSIRO)
# ABN 41 687 119 230.
#
# This software may be distributed and modified according to the terms of
# the BSD 2-Clause license. Note that NO WARRANTY is provided.
# See "LICENSE_BSD2.txt" for details.
#
# @TAG(DATA61_BSD)
#

cmake_minimum_required(VERSION 3.7.2)

project(libelf C)

add_library(elf EXCLUDE_FROM_ALL src/elf.c src/elf32.c src/elf64.c)
target_include_directories(elf PUBLIC inc)
target_link_libraries(elf rtl)
