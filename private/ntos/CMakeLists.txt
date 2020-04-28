cmake_minimum_required(VERSION 3.7.2)

project(ntos C ASM)

list(APPEND CMAKE_MODULE_PATH
    ${CMAKE_CURRENT_LIST_DIR}/../rtl
    ${CMAKE_CURRENT_LIST_DIR}/../../sel4)

find_package(seL4 REQUIRED)
include(${CMAKE_CURRENT_LIST_DIR}/cmake/sel4.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/cmake/flags.cmake)

find_package(rtl REQUIRED)
rtl_import_project()

set(configure_string "")
config_string(
    NtosRootStack
    NTOS_ROOT_STACK
    "Size of the initial stack for the ntos root thread"
    DEFAULT
    524288
    UNQUOTE
)
add_config_library(ntos "${configure_string}")

file(GLOB SRC ${CMAKE_CURRENT_LIST_DIR}/src/*/*.c ${CMAKE_CURRENT_LIST_DIR}/src/*/${Arch}/*.c ${CMAKE_CURRENT_LIST_DIR}/src/rtl/*/*.c ${CMAKE_CURRENT_LIST_DIR}/src/rtl/*/${Arch}/*.c ${CMAKE_CURRENT_LIST_DIR}/src/rtl/*/${Arch}/*.s ${CMAKE_CURRENT_LIST_DIR}/src/tests/*/*.c ${CMAKE_CURRENT_LIST_DIR}/src/*/${Arch}/*.S)

add_library(ntos STATIC ${SRC})
add_dependencies(ntos sel4 rtl)
target_include_directories(ntos PRIVATE inc inc/${Arch})
target_link_libraries(ntos PRIVATE sel4 sel4_autoconf rtl ntos_Config)

set_property(TARGET ntos APPEND_STRING PROPERTY LINK_FLAGS " -Wl,-T ${CMAKE_CURRENT_LIST_DIR}/ntos.lds ")

# Declare targets for building the final kernel image
set(
    KERNEL_IMAGE_NAME
    "${CMAKE_BINARY_DIR}/kernel-${KernelSel4Arch}-${KernelPlatform}"
)
if(Kernel64)
    add_custom_command(
        OUTPUT "${KERNEL_IMAGE_NAME}"
        COMMAND
            ${CMAKE_OBJCOPY} -O elf32-i386 $<TARGET_FILE:kernel.elf> "${KERNEL_IMAGE_NAME}"
        VERBATIM
        DEPENDS kernel.elf
        COMMENT "objcopy kernel into bootable elf"
    )
else()
    add_custom_command(
        OUTPUT "${KERNEL_IMAGE_NAME}"
        COMMAND cp $<TARGET_FILE:kernel.elf> "${KERNEL_IMAGE_NAME}"
        VERBATIM
        DEPENDS kernel.elf
    )
endif()

add_custom_target(
    all-elf ALL
    DEPENDS
        "${KERNEL_IMAGE_NAME}"
        kernel.elf
        ntos
)
