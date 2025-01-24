#
# Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
#
# SPDX-License-Identifier: BSD-2-Clause
#

cmake_minimum_required(VERSION 3.7.2)

project(elfloader C ASM)

include(../../sel4/tools/flags.cmake)
include(../../sel4/tools/helpers.cmake)
include(cpio.cmake)

if(${KernelArch} STREQUAL "arm")
set(KernelArchARM ON)
endif()

if(${KernelSel4Arch} STREQUAL "aarch64")
    set(KernelSel4ArchAarch64 ON)
    set(KernelWordSize 64)
    set(KernelArmArmV "armv8-a" CACHE INTERNAL "")
elseif(${KernelSel4Arch} STREQUAL "aarch32")
    set(KernelSel4ArchAarch32 ON)
    set(KernelWordSize 32)
    set(KernelArmArmV "armv7-a" CACHE INTERNAL "")
endif()

set(PYTHON3 "python3")
set(CONFIG_GEN_PATH "${CMAKE_CURRENT_LIST_DIR}/../../sel4/tools/config_gen.py")
set(configure_string "")
set(ElfloaderHashInstructions "hash_none")

set(binary_list
    "tx1;hikey;odroidc2;odroidc4;imx8mq-evk;imx8mm-evk;imx8mp-evk;hifive;tqma8xqp1gb;bcm2711;rocketchip")
set(efi_list "tk1;rockpro64;quartz64")
set(uimage_list "tx2;am335x")
if(${KernelPlatform} IN_LIST efi_list
   OR (${KernelPlatform} STREQUAL "hikey" AND ${KernelSel4Arch} STREQUAL "aarch64"))
    set(ElfloaderImage "efi" CACHE STRING "" FORCE)
elseif(${KernelPlatform} IN_LIST uimage_list)
    set(ElfloaderImage "uimage" CACHE STRING "" FORCE)
    #rpi3
elseif(${KernelPlatform} STREQUAL "bcm2837" AND ${KernelSel4Arch} STREQUAL "aarch64")
    set(ElfloaderImage "binary" CACHE STRING "" FORCE)
elseif(${KernelPlatform} IN_LIST binary_list)
    set(ElfloaderImage "binary" CACHE STRING "" FORCE)
else()
    set(ElfloaderImage "elf" CACHE STRING "" FORCE)
endif()

if(${KernelPlatform} STREQUAL "tk1" AND ${KernelSel4Arch} STREQUAL "arm_hyp")
    set(ElfloaderMode "hypervisor" CACHE STRING "" FORCE)
    set(ElfloaderMonitorHook ON CACHE BOOL "" FORCE)
endif()
if(${KernelPlatform} STREQUAL "bcm2711")
    set(IMAGE_START_ADDR 0x10000000 CACHE INTERNAL "" FORCE)
else()
    set(IMAGE_START_ADDR 0x80000000 CACHE INTERNAL "" FORCE)
endif()

config_choice(
    ElfloaderImage
    ELFLOADER_IMAGE
    "Boot image type"
    "elf;ElfloaderImageELF;IMAGE_ELF;KernelArchARM OR KernelArchRiscV"
    "binary;ElfloaderImageBinary;IMAGE_BINARY;KernelArchARM OR KernelArchRiscV"
    "efi;ElfloaderImageEFI;IMAGE_EFI;KernelArchARM"
    "uimage;ElfloaderImageUimage;IMAGE_UIMAGE;KernelArchARM"
)

config_choice(
    ElfloaderMode
    ELFLOADER_MODE
    "seL4 mode"
    "secure supervisor;ElfloaderModeSSup;ARM_S_SUPERVISOR_MODE;KernelPlatImx6"
    "monitor;ElfloaderModeMonitor;ARM_MONITOR_MODE;KernelPlatformTK1 OR KernelPlatImx6"
    "hypervisor;ElfloaderModeHyp;ARM_HYPERVISOR_MODE;KernelPlatformTK1"
    "non-secure supervisor;ElfloaderModeNSSup;ARM_NS_SUPERVISOR_MODE;KernelPlatformTK1 OR KernelPlatImx6"
)

config_option(
    ElfloaderMonitorHook ARM_MONITOR_HOOK "Install SMC call handlers in monitor mode."
    DEFAULT OFF
    DEPENDS "KernelPlatformTK1 OR KernelPlatImx6"
)

config_option(
    ElfloaderGPTPtimersNSPL1Access GPT_PTIMER_NS_PL1_ACCESS
    "Enable the GPT physical timer access for NS PL1"
    DEFAULT ON
    DEPENDS "ElfloaderModeNSSup"
    DEFAULT_DISABLED OFF
)

config_option(
    ElfloaderErrata764369 ARM_ERRATA_764369
    "Work around for a Cortex-A9 errata. Derived from Linux kernel."
    DEFAULT ON
    DEPENDS "KernelArmCortexA9"
    DEFAULT_DISABLED OFF
)

config_choice(
    ElfloaderHashInstructions
    HASH_INSTRUCTIONS
    "Perform a SHA256/MD5 Hash of the of each elf file that the elfloader checks on load"
    "hash_none;ElfloaderHashNone;HASH_NONE"
    "hash_sha;ElfloaderHashSHA;HASH_SHA"
    "hash_md5;ElfloaderHashMD5;HASH_MD5"
)

config_option(
    ElfloaderIncludeDtb ELFLOADER_INCLUDE_DTB
    "Include DTB in the CPIO in case bootloader doesn't provide one"
    DEFAULT ON
    DEPENDS "KernelArchARM OR KernelArchRiscV"
    DEFAULT_DISABLED OFF
)

add_config_library(elfloader "${configure_string}")

add_compile_options(-D_XOPEN_SOURCE=700 -ffreestanding -Wall -Werror -W -Wextra)
set(linkerScript "${CMAKE_CURRENT_LIST_DIR}/src/arch-${KernelArch}/linker.lds")
if(KernelArchRiscV)
    add_compile_options(-mcmodel=medany)
endif()

if(KernelSel4ArchAarch64)
    # NEON registers aren't necessarily initialized for use before elfloader starts
    add_compile_options(-mgeneral-regs-only)
endif()

# Don't allow unaligned data store/load instructions as this will cause an alignment
# fault before the MMU is turned on.
if(KernelSel4ArchAarch64)
    add_compile_options(-mstrict-align)
elseif(KernelSel4ArchAarch32)
    add_compile_options(-mno-unaligned-access)
endif()

if(KernelWordSize EQUAL 32)
    add_compile_options(-D__KERNEL_32__)
else()
    add_compile_options(-D__KERNEL_64__)
endif()

if(KernelArchARM)
    # Only the Arm arch uses extension drivers.
    set(
        driver_file_globs
        src/drivers/*.c
        src/drivers/smp/*.c
        src/drivers/uart/*.c
        src/drivers/timer/*.c
    )
endif()

file(
    GLOB
        files
        src/*.c
        ${driver_file_globs}
        src/utils/*.c
        src/arch-${KernelArch}/*.c
        src/arch-${KernelArch}/*.S
        src/arch-${KernelArch}/drivers/*.c
        src/plat/${KernelPlatform}/*.c
        src/binaries/elf/*.c
        src/arch-${KernelArch}/${KernelWordSize}/*.c
        src/plat/${KernelPlatform}/*.S
        src/arch-${KernelArch}/${KernelWordSize}/*.S
)

# We never want to give crt0_64.S to add_executable
list(FILTER files EXCLUDE REGEX "src/arch-arm/32/crt0_64\.S")

if(NOT ElfloaderMonitorHook)
    # The CMake documentation is no clear on this, but it seems all variables
    # of the form ${xxx} get evaluated first and then the regex is applied
    list(FILTER files EXCLUDE REGEX "src/plat/${KernelPlatform}/monitor\.S")
endif()

if(KernelArchARM)
    file(
        GLOB
            arm_files src/arch-${KernelArch}/armv/${KernelArmArmV}/${KernelWordSize}/*.c
            src/arch-${KernelArch}/armv/${KernelArmArmV}/${KernelWordSize}/*.S
    )
    list(APPEND files ${arm_files})
endif()

# Prevent any global variables to be placed in *COM* instead of .bss.
# This causes linker errors for duplicate symbol definitions correctly
# and allows the _bss and _bss_end symbols to capture all .bss variables properly.
add_compile_options(-fno-common)
if(ElfloaderImageEFI)
    # We cannot control where EFI loads the image and so we must make it relocatable
    add_compile_options(-fpic)
    if(KernelSel4ArchAarch32)
        set(gnuefiArch "arm")
        # on aarch32 building with -fno-pie results in the compiler generating
        # movt/movw pairs that we can't easily relocate.
        add_compile_options(-fpie)
        # This flag is not supported by clang but add it in for gcc
        if(NOT CMAKE_C_COMPILER_ID STREQUAL "Clang")
            add_compile_options(-mno-single-pic-base)
        endif()
    else()
        set(gnuefiArch "aarch64")
        # on aarch64 building with -fno-pie will just use pc-relative addressing.
        add_compile_options(-fno-pie -fPIC)
    endif()

    file(GLOB efi_files src/binaries/efi/*.c)
    list(
        APPEND
            files
            ${efi_files}
            src/binaries/efi/gnuefi/crt0-efi-${gnuefiArch}.S
            src/binaries/efi/gnuefi/reloc_${gnuefiArch}.c
    )
    # We use gnu-efi's linker script on EFI.
    set(linkerScript ${CMAKE_CURRENT_LIST_DIR}/src/binaries/efi/gnuefi/elf_${gnuefiArch}_efi.lds)
else()
    add_compile_options(-fno-pic)
    add_compile_options(-fno-pie)
endif()

# Sort files to make build reproducible
list(SORT files)

set(cpio_files "")
list(APPEND cpio_files "${KERNEL_IMAGE}")
if(ElfloaderIncludeDtb)
    list(APPEND cpio_files "${KernelDTBPath}")
endif()
list(APPEND cpio_files "${NTOS_IMAGE}")
if(NOT ${ElfloaderHashInstructions} STREQUAL "hash_none")
    set(hash_command "")
    if(ElfloaderHashSHA)
        set(hash_command "sha256sum")
    else()
        set(hash_command "md5sum")
    endif()
    add_custom_command(
        OUTPUT "kernel.bin"
        COMMAND
            bash -c
            "${hash_command} ${KERNEL_IMAGE} | cut -d ' ' -f 1 | xxd -r -p > ${CMAKE_CURRENT_BINARY_DIR}/kernel.bin"
        VERBATIM
    )
    add_custom_command(
        OUTPUT "app.bin"
        COMMAND
            bash -c
            "${hash_command} ${NTOS_IMAGE} | cut -d ' ' -f 1 | xxd -r -p > ${CMAKE_CURRENT_BINARY_DIR}/app.bin"
        VERBATIM
    )
    list(APPEND cpio_files "${CMAKE_CURRENT_BINARY_DIR}/kernel.bin")
    list(APPEND cpio_files "${CMAKE_CURRENT_BINARY_DIR}/app.bin")
endif()

# Construct the ELF loader's payload.
MakeCPIO(archive.o "${cpio_files}" CPIO_SYMBOL _archive_start)

set(PLATFORM_HEADER_DIR "${CMAKE_CURRENT_BINARY_DIR}/gen_headers")
set(PLATFORM_INFO_H "${PLATFORM_HEADER_DIR}/platform_info.h")
set(IMAGE_START_ADDR_H "${PLATFORM_HEADER_DIR}/image_start_addr.h")

if(NOT "${IMAGE_START_ADDR}" STREQUAL "")
    # Generate static header files.  Their timestamps will change only if
    # their contents have changed on subsequent CMake reruns.
    file(GENERATE OUTPUT ${PLATFORM_INFO_H} CONTENT "
#pragma once
")
    file(GENERATE OUTPUT ${IMAGE_START_ADDR_H} CONTENT "
#pragma once
#define IMAGE_START_ADDR ${IMAGE_START_ADDR}
")
else()
    message(FATAL_ERROR "IMAGE_START_ADDR not set")
endif()

if(DEFINED KernelDTBPath)
    get_filename_component(KernelTools ${HARDWARE_GEN_PATH} DIRECTORY)
    set(config_file "${KernelTools}/hardware.yml")
    set(schema_file "${KernelTools}/hardware_schema.yml")
    set(DEVICES_GEN_H "${PLATFORM_HEADER_DIR}/devices_gen.h")
    add_custom_command(
        OUTPUT ${DEVICES_GEN_H}
        COMMAND
            ${PYTHON3} ${HARDWARE_GEN_PATH}
            --elfloader
            --elfloader-out "${DEVICES_GEN_H}"
            --hardware-config "${config_file}"
            --hardware-schema "${schema_file}"
            --dtb "${KernelDTBPath}"
            --sel4arch "${KernelSel4Arch}"
        VERBATIM
        DEPENDS ${KernelDTBPath} ${config_file} ${schema_file}
    )
    set_property(SOURCE src/drivers/driver.c PROPERTY OBJECT_DEPENDS ${DEVICES_GEN_H})
endif()

# Generate linker script
separate_arguments(c_arguments NATIVE_COMMAND "${CMAKE_C_FLAGS}")
# Add extra compilation flags required for clang
if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
    list(APPEND c_arguments "${CMAKE_C_COMPILE_OPTIONS_TARGET}${CMAKE_C_COMPILER_TARGET}")
endif()
add_custom_command(
    OUTPUT "linker.lds_pp"
    COMMAND
        ${CMAKE_C_COMPILER} "${c_arguments}" "-I${PLATFORM_HEADER_DIR}" "-I${KERNEL_GEN_CONFIG_DIR}"
        "-I$<JOIN:$<TARGET_PROPERTY:elfloader_Config,INTERFACE_INCLUDE_DIRECTORIES>,;-I>" -P -E -o
        linker.lds_pp -x c ${linkerScript}
    DEPENDS
        ${linkerScript}
        elfloader_Config
        ${IMAGE_START_ADDR_H}
    VERBATIM COMMAND_EXPAND_LISTS
)
add_custom_target(elfloader_linker DEPENDS linker.lds_pp)

add_executable(elfloader EXCLUDE_FROM_ALL ${files} archive.o)

if(ElfloaderImageEFI)
    set_target_properties(elfloader PROPERTIES LINK_DEPENDS ${linkerScript})
    set_property(
        TARGET elfloader
        APPEND_STRING
        PROPERTY
            LINK_FLAGS
	    # --shared builds a shared library (with the _DYNAMIC and _end symbol)
            # -Bsymbolic forces symbols to bind to their definitions within the elfloader
            # EFI_SUBSYSTEM=0xa indicates that we're building an EFI application.
            " -fuse-ld=lld -Wl,-T ${linkerScript} -Wl,--shared -nostdlib -Wl,-Bsymbolic,--defsym=EFI_SUBSYSTEM=0xa -Wl,--build-id=none"
    )
    add_custom_command(
        OUTPUT "elfloader-bin"
            COMMAND
                llvm-objcopy -O binary elfloader elfloader-bin
            DEPENDS elfloader
    )
else()
    set_target_properties(
        elfloader
        PROPERTIES LINK_DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/linker.lds_pp
    )
    add_dependencies(elfloader elfloader_linker)
    set_property(
        TARGET elfloader
        APPEND_STRING
        PROPERTY
            LINK_FLAGS
            " -Wl,-T ${CMAKE_CURRENT_BINARY_DIR}/linker.lds_pp -nostdlib -static -Wl,--build-id=none -Wl,-z -Wl,max-page-size=0x1000"
    )
    add_custom_command(
        OUTPUT "elfloader-bin"
            COMMAND
                cp elfloader elfloader-bin
            DEPENDS elfloader
    )
endif()

target_include_directories(
    elfloader
    PUBLIC
        "${KERNEL_GEN_CONFIG_DIR}"
    PRIVATE
        "include"
        "include/plat/${KernelPlatform}"
        "include/arch-${KernelArch}"
        "include/arch-${KernelArch}/${KernelWordSize}"
        "${CMAKE_CURRENT_BINARY_DIR}/gen_headers"
        "${CMAKE_CURRENT_BINARY_DIR}"
)
if(KernelArchARM)
    target_include_directories(
        elfloader
        PRIVATE
            "include/arch-${KernelArch}/armv/${KernelArmArmV}"
            "include/arch-${KernelArch}/armv/${KernelArmArmV}/${KernelWordSize}"
    )
endif()

target_link_libraries(
    elfloader
    PRIVATE
        elfloader_Config
)

add_custom_target(
    bootimg ALL
    DEPENDS
        elfloader
        "elfloader-bin"
)
