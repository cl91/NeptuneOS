cmake_minimum_required(VERSION 3.7.2)

project(ntsvc C ASM)

list(APPEND CMAKE_MODULE_PATH
    ${CMAKE_CURRENT_LIST_DIR}/../../sel4
    ${CMAKE_CURRENT_LIST_DIR}/../rtl
    ${CMAKE_CURRENT_LIST_DIR}/lib)

find_package(seL4 REQUIRED)
include(${CMAKE_CURRENT_LIST_DIR}/cmake/sel4.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/cmake/flags.cmake)

find_package(rtl REQUIRED)
rtl_import_project()

add_subdirectory(lib)

set(configure_string "")
config_string(
    Sel4RuntimeRootStack
    SEL4RUNTIME_ROOT_STACK
    "Size of the initial stack for the root task"
    DEFAULT
    16384
    UNQUOTE
)
add_config_library(ntsvc "${configure_string}")

add_executable(ntsvc src/ke/${Arch}/entry.S src/ke/init.c)
add_dependencies(ntsvc sel4 rtl)
target_include_directories(ntsvc PUBLIC inc inc/${Arch})
target_link_libraries(ntsvc PUBLIC sel4 sel4_autoconf rtl cpio elf PRIVATE ntsvc_Config)

set_property(TARGET ntsvc APPEND_STRING PROPERTY LINK_FLAGS " -Wl,-u_KiSystemStartup -Wl,-e_KiSystemStartup -Wl,-T ${CMAKE_CURRENT_LIST_DIR}/ntsvc.lds ")

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
