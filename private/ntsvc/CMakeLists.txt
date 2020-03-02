cmake_minimum_required(VERSION 3.7.2)

project(ntsvc C ASM)

list(APPEND CMAKE_MODULE_PATH
    ${CMAKE_CURRENT_LIST_DIR}/../../sel4
    ${CMAKE_CURRENT_LIST_DIR}/rtl)

# Make build options a visible choice, default it to Debug
set(CMAKE_BUILD_TYPE "Debug")

find_package(seL4 REQUIRED)
include(${CMAKE_CURRENT_LIST_DIR}/cmake/sel4.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/cmake/flags.cmake)

find_package(sel4runtime REQUIRED)
sel4runtime_import_project()

add_executable(ntsvc src/main.c)
add_dependencies(ntsvc sel4 sel4runtime)
target_link_libraries(ntsvc sel4 sel4_autoconf sel4runtime)

set_property(TARGET ntsvc APPEND_STRING PROPERTY LINK_FLAGS " -Wl,-u_sel4_start -Wl,-e_sel4_start -Wl,-T ${CMAKE_CURRENT_LIST_DIR}/${KernelSel4Arch}.lds ")

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
    all-pe ALL
    DEPENDS
        "${KERNEL_IMAGE_NAME}"
        kernel.elf
        ntsvc
)
