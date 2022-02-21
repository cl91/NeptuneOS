cmake_minimum_required(VERSION 3.7.2)

set(CMAKE_SYSTEM_NAME Windows)

project(wdm C ASM)

list(APPEND CMAKE_MODULE_PATH
    ${CMAKE_CURRENT_LIST_DIR}/../rtl)

include(${CMAKE_CURRENT_LIST_DIR}/../../tools/cmake/spec2def.cmake)

add_compile_options(
    -nostdinc
    -fno-pic
    -fno-pie
    -Wno-incompatible-library-redeclaration
    -msoft-float
    -mno-sse
    -mno-mmx
    --target=${TRIPLE}
    -DGIT_HEAD_SHA_SHORT=\"${GIT_HEAD_SHA_SHORT}\"
    -D_NTSYSTEM_
)
set(CMAKE_C_FLAGS_DEBUG "-g -Xclang -gcodeview -O0 -D_DEBUG -DDBG -UNDEBUG" CACHE STRING "" FORCE)
set(CMAKE_C_FLAGS_MINSIZEREL "-Os -DNDEBUG -Xclang -gcodeview" CACHE STRING "" FORCE)
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG -Xclang -gcodeview" CACHE STRING "" FORCE)
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

add_library(wdm SHARED ${SRC})
add_dependencies(wdm rtl)
target_link_directories(wdm PRIVATE ${NDK_LIB_PATH})
target_link_libraries(wdm PRIVATE rtl)

add_library(genincdata MODULE tools/genincdata.c)
set_entrypoint(genincdata 0)
target_include_directories(
    genincdata
    PRIVATE
	../../public/ndk/inc
	../../public/ddk/inc
	../../public/crt/inc
	../../public/crt/inc/${Arch}
	../rtl/inc
	tools
	inc
)
add_dependencies(genincdata rtl)
add_custom_target(
    geninc ALL
    COMMAND ${GENINC_PATH} $<TARGET_FILE:genincdata> ${CMAKE_CURRENT_BINARY_DIR}/wdmasm.h
    DEPENDS genincdata
)
add_dependencies(wdm geninc)

spec2def(wdm wdm.spec ${Arch})
set_dll_def(wdm wdm.def)
set_entrypoint(wdm WdmStartup)

target_include_directories(
    wdm
    PRIVATE
	${STRUCTURES_GEN_DIR}
	${GEN_INC_DIR}
	${CMAKE_CURRENT_BINARY_DIR}
	inc
	../../public/ddk/inc
	../../sel4/libsel4/include
	../../sel4/libsel4/mode_include/${KernelWordSize}
	../../sel4/libsel4/sel4_plat_include/${KernelPlatform}
	../../sel4/libsel4/arch_include/${KernelArch}
	${SANITIZED_SEL4_ARCH_INCLUDE_DIR}
	${SEL4_GENERATED_HEADERS_DIR}/kernel/gen_config
	${SEL4_GENERATED_HEADERS_DIR}/libsel4/gen_config
	${SEL4_GENERATED_HEADERS_DIR}/libsel4/autoconf
	${SEL4_GENERATED_HEADERS_DIR}/libsel4/include
	${SEL4_GENERATED_HEADERS_DIR}/libsel4/arch_include/${KernelArch}
	${SEL4_GENERATED_HEADERS_DIR}/libsel4/sel4_arch_include/${KernelSel4Arch}
)
