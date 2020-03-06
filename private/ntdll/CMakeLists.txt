cmake_minimum_required(VERSION 3.7.2)

project(ntdll C ASM)

list(APPEND CMAKE_MODULE_PATH
    ${CMAKE_CURRENT_LIST_DIR}/../rtl)

find_package(rtl REQUIRED)
rtl_import_project()

set(configure_string "")
config_string(
    Sel4RuntimeStaticTLS
    SEL4RUNTIME_STATIC_TLS
    "Size of static TLS area for new processes"
    DEFAULT
    16384
    UNQUOTE
)
add_config_library(ntdll "${configure_string}")

add_executable(ntdll src/main.c src/ldr/${Arch}/entry.c src/ldr/init.c)
add_dependencies(ntdll rtl)
target_link_libraries(ntdll rtl PRIVATE ntdll_Config)

set_property(TARGET ntdll APPEND_STRING PROPERTY LINK_FLAGS " -Wl,-u_LdrInitializeThunk -Wl,-e_LdrInitializeThunk ")
