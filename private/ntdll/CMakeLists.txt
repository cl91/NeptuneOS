cmake_minimum_required(VERSION 3.7.2)

set(CMAKE_SYSTEM_NAME Windows)

project(ntdll C ASM)

list(APPEND CMAKE_MODULE_PATH
    ${CMAKE_CURRENT_LIST_DIR}/../rtl)

include(${CMAKE_CURRENT_LIST_DIR}/../../tools/cmake/spec2def.cmake)

add_compile_options(
    -nostdinc
    -fno-pic
    -fno-pie
    -Wno-incompatible-library-redeclaration
    --target=${TRIPLE}
)
set(CMAKE_C_FLAGS_DEBUG "-g -Xclang -gcodeview -O0 -D_DEBUG" CACHE STRING "" FORCE)
set(CMAKE_C_FLAGS_MINSIZEREL "-Os -DNDEBUG" CACHE STRING "" FORCE)
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG" CACHE STRING "" FORCE)
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g -DNDEBUG -Xclang -gcodeview" CACHE STRING "" FORCE)
mark_as_advanced(CMAKE_C_FLAGS_DEBUG)
mark_as_advanced(CMAKE_C_FLAGS_MINSIZEREL)
mark_as_advanced(CMAKE_C_FLAGS_RELEASE)
mark_as_advanced(CMAKE_C_FLAGS_RELWITHDEBINFO)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-stack-protector -fno-asynchronous-unwind-tables -ftls-model=global-dynamic")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -nostdinc++")
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_LIBRARIES "" CACHE STRING "" FORCE)
set(CMAKE_CXX_STANDARD_LIBRARIES "" CACHE STRING "" FORCE)
mark_as_advanced(CMAKE_C_STANDARD_LIBRARIES)
mark_as_advanced(CMAKE_CXX_STANDARD_LIBRARIES)
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} --target=${TRIPLE} -fuse-ld=lld-link -static -nostdlib -Wl,-force:multiple -Wl,-subsystem:native -Wl,-safeseh:no"
)

set(KernelPlatform "pc99")
set(KernelArch "x86")
if(Arch STREQUAL "i386")
    set(KernelWordSize 32)
    set(KernelSel4Arch "ia32")
    set(GENINC_FILENAME "ks386.h")
elseif(Arch STREQUAL "amd64")
    set(KernelWordSize 64)
    set(KernelSel4Arch "x86_64")
    set(GENINC_FILENAME "ksamd64.h")
else()
    message(FATAL_ERROR "Unsupported architecture: ${Arch}")
endif()

find_package(rtl REQUIRED)
rtl_import_project()

file(GLOB SRC ${CMAKE_CURRENT_LIST_DIR}/src/*/*.c ${CMAKE_CURRENT_LIST_DIR}/src/*/${Arch}/*.c ${CMAKE_CURRENT_LIST_DIR}/src/*/${Arch}/*.S)

add_library(ntdll SHARED ${SRC})
add_dependencies(ntdll rtl)
target_link_libraries(ntdll PRIVATE rtl)

spec2def(ntdll ntdll.spec)
set_dll_def(ntdll ntdll.def)
set_entrypoint(ntdll LdrInitializeThunk)

add_library(genincdata MODULE tools/genincdata.c)
set_entrypoint(genincdata 0)
target_include_directories(
    genincdata
    PRIVATE
    	../../public/ndk/inc
	../../public/crt/inc
	../../public/crt/inc/${Arch}
	tools
)
add_custom_target(
    geninc ALL
    COMMAND ${GENINC_PATH} $<TARGET_FILE:genincdata> ${CMAKE_CURRENT_BINARY_DIR}/${GENINC_FILENAME}
    DEPENDS genincdata)
add_dependencies(ntdll geninc)

target_include_directories(
    ntdll
    PRIVATE
	${STRUCTURES_GEN_DIR}
	${CMAKE_CURRENT_BINARY_DIR}
	${CMAKE_CURRENT_LIST_DIR}/inc
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
