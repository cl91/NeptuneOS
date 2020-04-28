cmake_minimum_required(VERSION 3.7.2)

project(ntdll C ASM)

list(APPEND CMAKE_MODULE_PATH
    ${CMAKE_CURRENT_LIST_DIR}/../ntos)

add_compile_options(
    -nostdinc
    -fno-pic
    -fno-pie
    -fno-stack-protector
    -fno-asynchronous-unwind-tables
    -ftls-model=local-exec
    -Wno-incompatible-library-redeclaration
)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -nostdinc++")
set(CMAKE_C_STANDARD 11)
set(
    CMAKE_EXE_LINKER_FLAGS
    "${CMAKE_EXE_LINKER_FLAGS} -fuse-ld=lld -static -nostdlib -Wl,-force:multiple"
)

set(KernelPlatform "pc99")
set(KernelArch "x86")
if(Arch STREQUAL "i386")
    set(KernelWordSize 32)
    set(KernelSel4Arch "ia32")
elseif(Arch STREQUAL "amd64")
    set(KernelWordSize 64)
    set(KernelSel4Arch "x86_64")
else()
    message(FATAL_ERROR "Unsupported architecture: ${Arch}")
endif()

find_package(ntos REQUIRED)
ntos_import_project()

file(GLOB SRC ${CMAKE_CURRENT_LIST_DIR}/src/*/*.c ${CMAKE_CURRENT_LIST_DIR}/src/*/${Arch}/*.c ${CMAKE_CURRENT_LIST_DIR}/src/*/${Arch}/*.S)

add_executable(ntdll ${SRC})
add_dependencies(ntdll ntos)
target_link_libraries(ntdll PUBLIC ntos)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -nostdinc++")
set(CMAKE_C_STANDARD 11)

set_property(TARGET ntdll APPEND_STRING PROPERTY LINK_FLAGS " -Wl,-subsystem:native -Wl,-safeseh:no -Wl,-entry:LdrInitializeThunk ")
