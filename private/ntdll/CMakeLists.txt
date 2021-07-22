cmake_minimum_required(VERSION 3.7.2)

project(ntdll C ASM)

list(APPEND CMAKE_MODULE_PATH
    ${CMAKE_CURRENT_LIST_DIR}/../rtl)

add_compile_options(
    -nostdinc
    -fno-pic
    -fno-pie
    -fno-stack-protector
    -fno-asynchronous-unwind-tables
    -ftls-model=local-exec
    -Wno-incompatible-library-redeclaration
    --target=${TRIPLE}
)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -nostdinc++")
set(CMAKE_C_STANDARD 11)
set(
    CMAKE_EXE_LINKER_FLAGS
    "${CMAKE_EXE_LINKER_FLAGS} --target=${TRIPLE} -fuse-ld=lld-link -static -nostdlib -Wl,-force:multiple"
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

find_package(rtl REQUIRED)
rtl_import_project()

file(GLOB SRC ${CMAKE_CURRENT_LIST_DIR}/src/*/*.c ${CMAKE_CURRENT_LIST_DIR}/src/*/${Arch}/*.c ${CMAKE_CURRENT_LIST_DIR}/src/*/${Arch}/*.S)

add_executable(ntdll ${SRC})
add_dependencies(ntdll rtl)
target_link_libraries(ntdll PRIVATE rtl)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -nostdinc++")
set(CMAKE_C_STANDARD 11)

set_property(TARGET ntdll APPEND_STRING PROPERTY LINK_FLAGS " -Wl,-subsystem:native -Wl,-safeseh:no -Wl,-entry:LdrInitializeThunk ")

target_include_directories(
    ntdll
    PRIVATE
	${CMAKE_CURRENT_LIST_DIR}/../../sel4/libsel4/include
	${CMAKE_CURRENT_LIST_DIR}/../../sel4/libsel4/mode_include/${KernelWordSize}
	${CMAKE_CURRENT_LIST_DIR}/../../sel4/libsel4/sel4_plat_include/${KernelPlatform}
	${CMAKE_CURRENT_LIST_DIR}/../../sel4/libsel4/arch_include/${KernelArch}
	${LIBSEL4_PE_HEADERS_DIR}/sel4_arch_include
	${LIBSEL4_PE_HEADERS_DIR}/generated/kernelconfig
	${LIBSEL4_PE_HEADERS_DIR}/generated/gen_config
	${LIBSEL4_PE_HEADERS_DIR}/generated/autoconf
	${LIBSEL4_PE_HEADERS_DIR}/generated/include
	${LIBSEL4_PE_HEADERS_DIR}/generated/arch_include/${KernelArch}
	${LIBSEL4_PE_HEADERS_DIR}/generated/sel4_arch_include/${KernelSel4Arch}
)
