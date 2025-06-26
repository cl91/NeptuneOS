cmake_minimum_required(VERSION 3.12.0)

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
    "Size of the initial stack for the ntos root task"
    DEFAULT
    1048576
    UNQUOTE
)
add_config_library(ntos "${configure_string}")

file(GLOB SRC ${CMAKE_CURRENT_LIST_DIR}/src/*/*.c ${CMAKE_CURRENT_LIST_DIR}/src/*/${Arch}/*.c ${CMAKE_CURRENT_LIST_DIR}/src/rtl/*/*.c ${CMAKE_CURRENT_LIST_DIR}/src/rtl/*/${Arch}/*.c ${CMAKE_CURRENT_LIST_DIR}/src/rtl/*/${Arch}/*.s ${CMAKE_CURRENT_LIST_DIR}/src/tests/*/*.c ${CMAKE_CURRENT_LIST_DIR}/src/*/${Arch}/*.S)

add_custom_target(
    structures_gen ALL
    COMMAND sed -n "/enum cap_tag {/,/typedef enum cap_tag cap_tag_t/p" ${STRUCTURES_GEN_H_ORIG} > ${STRUCTURES_GEN_DIR}/structures_gen.h
    VERBATIM
    DEPENDS kernel.elf
)

# lld does not like the linker script of the seL4 kernel on x86 platforms,
# so force clang to use ld to link the seL4 kernel elf
if ("${Arch}" MATCHES "^(i386|amd64)$")
   set_property(TARGET kernel.elf APPEND_STRING PROPERTY LINK_FLAGS " -fuse-ld=ld ")
endif()

add_dependencies(rtl structures_gen)
add_library(ntos STATIC ${SRC})
add_dependencies(ntos sel4 rtl kernel.elf)
target_include_directories(ntos PRIVATE inc inc/${Arch} ${STRUCTURES_GEN_DIR})
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
            ${CMAKE_OBJCOPY} -O ${OUTPUT_TARGET} $<TARGET_FILE:kernel.elf> "${KERNEL_IMAGE_NAME}"
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
