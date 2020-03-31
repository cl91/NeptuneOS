cmake_minimum_required(VERSION 3.7.2)

project(ntdll C ASM)

list(APPEND CMAKE_MODULE_PATH
    ${CMAKE_CURRENT_LIST_DIR}/../rtl)

find_package(rtl REQUIRED)
rtl_import_project()

add_executable(ntdll src/main.c src/ldr/${Arch}/entry.c src/ldr/init.c)
add_dependencies(ntdll rtl ntos)
target_link_libraries(ntdll PUBLIC rtl ntos)

set_property(TARGET ntdll APPEND_STRING PROPERTY LINK_FLAGS " -Wl,-u_LdrInitializeThunk -Wl,-e_LdrInitializeThunk ")
