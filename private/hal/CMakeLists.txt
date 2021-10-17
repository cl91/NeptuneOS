cmake_minimum_required(VERSION 3.7.2)

set(CMAKE_SYSTEM_NAME Windows)

project(hal C ASM)

list(APPEND CMAKE_MODULE_PATH
    ${CMAKE_CURRENT_LIST_DIR}/../rtl)

include(${CMAKE_CURRENT_LIST_DIR}/../../tools/cmake/spec2def.cmake)

add_compile_options(
    -nostdinc
    -fno-pic
    -fno-pie
    -Wno-incompatible-library-redeclaration
    --target=${TRIPLE}
    -D_NTSYSTEM_
)
set(CMAKE_C_FLAGS_DEBUG "-g -Xclang -gcodeview -O0 -D_DEBUG" CACHE STRING "" FORCE)
set(CMAKE_C_FLAGS_MINSIZEREL "-Os -DNDEBUG" CACHE STRING "" FORCE)
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG" CACHE STRING "" FORCE)
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g -DNDEBUG -Xclang -gcodeview" CACHE STRING "" FORCE)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-stack-protector -fno-asynchronous-unwind-tables -ftls-model=global-dynamic")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -nostdinc++")
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_LIBRARIES "" CACHE STRING "" FORCE)
set(CMAKE_CXX_STANDARD_LIBRARIES "" CACHE STRING "" FORCE)
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} --target=${TRIPLE} -lntdll -fuse-ld=lld-link -nostdlib -Wl,-subsystem:native -Wl,-safeseh:no -Wl,-errorlimit:0 -Wl,/merge:.data=.tls"
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

file(GLOB SRC ${CMAKE_CURRENT_LIST_DIR}/src/*.c ${CMAKE_CURRENT_LIST_DIR}/src/${Arch}/*.c ${CMAKE_CURRENT_LIST_DIR}/src/${Arch}/*.S)

add_library(hal SHARED ${SRC})
add_dependencies(hal rtl)
target_link_directories(hal PRIVATE ${NDK_LIB_PATH})
target_link_libraries(hal PRIVATE rtl)

spec2def(hal hal.spec ${Arch})
set_dll_def(hal hal.def)
set_entrypoint(hal HalStartup)

target_include_directories(
    hal
    PRIVATE
	${STRUCTURES_GEN_DIR}
	${GEN_INC_DIR}
	${CMAKE_CURRENT_BINARY_DIR}
	${CMAKE_CURRENT_LIST_DIR}/inc
	${CMAKE_CURRENT_LIST_DIR}/../../public/ddk/inc
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
