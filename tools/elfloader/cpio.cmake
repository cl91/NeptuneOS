#
# Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
#
# SPDX-License-Identifier: BSD-2-Clause
#

# This module contains functions for creating a cpio archive containing a list
# of input files and turning it into an object file that can be linked into a binary.

include_guard(GLOBAL)

# Checks the existence of an argument to cpio -o.
# flag refers to a variable in the parent scope that contains the argument, if
# the argument isn't supported then the flag is set to the empty string in the parent scope.
function(CheckCPIOArgument var flag)
    if(NOT (DEFINED ${var}))
        file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/cpio-testfile "Testfile contents")
        execute_process(
            COMMAND bash -c "echo cpio-testfile | cpio ${flag} -o"
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            OUTPUT_QUIET ERROR_QUIET
            RESULT_VARIABLE result
        )
        if(result)
            set(${var} "" CACHE INTERNAL "")
            message(STATUS "CPIO test ${var} FAILED")
        else()
            set(${var} "${flag}" CACHE INTERNAL "")
            message(STATUS "CPIO test ${var} PASSED")
        endif()
        file(REMOVE ${CMAKE_CURRENT_BINARY_DIR}/cpio-testfile)
    endif()
endfunction()

# Function for declaring rules to build a cpio archive that can be linked
# into another target
function(MakeCPIO output_name input_files)
    cmake_parse_arguments(PARSE_ARGV 2 MAKE_CPIO "" "CPIO_SYMBOL" "DEPENDS")
    if(NOT "${MAKE_CPIO_UNPARSED_ARGUMENTS}" STREQUAL "")
        message(FATAL_ERROR "Unknown arguments to MakeCPIO")
    endif()
    set(archive_symbol "_cpio_archive")
    if(NOT "${MAKE_CPIO_CPIO_SYMBOL}" STREQUAL "")
        set(archive_symbol ${MAKE_CPIO_CPIO_SYMBOL})
    endif()
    # Check that the reproducible flag is available. Don't use it if it isn't.
    CheckCPIOArgument(cpio_reproducible_flag "--reproducible")
    set(
        commands
        "bash;-c;cpio ${cpio_reproducible_flag} --quiet --create -H newc --file=${CMAKE_CURRENT_BINARY_DIR}/archive.${output_name}.cpio;&&"
    )
    foreach(file IN LISTS input_files)
        # Try and generate reproducible cpio meta-data as we do this:
        # - touch -d @0 file sets the modified time to 0
        # - --owner=root:root sets user and group values to 0:0
        # - --reproducible creates reproducible archives with consistent inodes and device numbering
        list(
            APPEND
                commands
                "bash;-c; mkdir -p temp_${output_name} && cd temp_${output_name} && cp -a ${file} . && touch -d 1970-01-01T00:00:00Z `basename ${file}` && echo `basename ${file}` | cpio --append ${cpio_reproducible_flag} --owner=+0:+0 --quiet -o -H newc --file=${CMAKE_CURRENT_BINARY_DIR}/archive.${output_name}.cpio && rm `basename ${file}` && cd ../ && rmdir temp_${output_name};&&"
        )
    endforeach()
    list(APPEND commands "true")
    separate_arguments(cmake_c_flags_sep NATIVE_COMMAND "${CMAKE_C_FLAGS}")
    if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
        list(APPEND cmake_c_flags_sep "${CMAKE_C_COMPILE_OPTIONS_TARGET}${CMAKE_C_COMPILER_TARGET}")
    endif()

    add_custom_command(
        OUTPUT ${output_name}
        COMMAND rm -f archive.${output_name}.cpio
        COMMAND ${commands}
        COMMAND
            sh -c
            "echo 'X.section ._archive_cpio,\"aw\"X.globl ${archive_symbol}, ${archive_symbol}_endX${archive_symbol}:X.incbin \"archive.${output_name}.cpio\"X${archive_symbol}_end:X' | tr X '\\n'"
            > ${output_name}.S
        COMMAND
            ${CMAKE_C_COMPILER} ${cmake_c_flags_sep} -c -o ${output_name} ${output_name}.S
        DEPENDS ${input_files} ${MAKE_CPIO_DEPENDS}
        VERBATIM
        BYPRODUCTS
        archive.${output_name}.cpio
        ${output_name}.S
        COMMENT "Generate CPIO archive ${output_name}"
    )
endfunction(MakeCPIO)
