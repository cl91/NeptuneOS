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
    -msoft-float
    -mno-sse
    -mno-mmx
    --target=${TRIPLE}
    -DGIT_HEAD_SHA_SHORT=\"${GIT_HEAD_SHA_SHORT}\"
    -D_NTDLL_
    -D_NTSYSTEM_
)
set(CMAKE_C_FLAGS_DEBUG "-g -Xclang -gcodeview -O0 -D_DEBUG -DDBG -DDEBUG" CACHE STRING "" FORCE)
set(CMAKE_C_FLAGS_MINSIZEREL "-Os -DNDEBUG -Xclang -gcodeview" CACHE STRING "" FORCE)
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG -Xclang -gcodeview" CACHE STRING "" FORCE)
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g -DNDEBUG -Xclang -gcodeview" CACHE STRING "" FORCE)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-stack-protector -fno-asynchronous-unwind-tables -ftls-model=global-dynamic")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -nostdinc++")
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_LIBRARIES "" CACHE STRING "" FORCE)
set(CMAKE_CXX_STANDARD_LIBRARIES "" CACHE STRING "" FORCE)
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} --target=${TRIPLE} -fuse-ld=lld-link -nostdlib -Wl,-subsystem:native -Wl,-safeseh:no -Wl,-errorlimit:0"
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

file(GLOB SRC ${CMAKE_CURRENT_LIST_DIR}/src/*/*.c ${CMAKE_CURRENT_LIST_DIR}/src/crt/*/*.c ${CMAKE_CURRENT_LIST_DIR}/src/*/${Arch}/*.c ${CMAKE_CURRENT_LIST_DIR}/src/*/${Arch}/*.S ${CMAKE_CURRENT_LIST_DIR}/src/crt/*/${Arch}/*.S)

file(GLOB NTDLLP_SRC ${CMAKE_CURRENT_LIST_DIR}/src/crt/math/${Arch}/*.S ${CMAKE_CURRENT_LIST_DIR}/src/crt/except/${Arch}/*.S)

add_library(ntdll SHARED ${SRC})
add_library(ntdllp STATIC ${NTDLLP_SRC})
add_dependencies(ntdll rtl)
target_link_libraries(ntdll PRIVATE rtl)

spec2def(ntdll ntdll.spec ${Arch})
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
    DEPENDS genincdata
)
add_dependencies(ntdll geninc)
add_dependencies(ntdllp geninc)

target_include_directories(
    ntdll
    PRIVATE
	${STRUCTURES_GEN_DIR}
	${CMAKE_CURRENT_BINARY_DIR}
	inc
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
target_include_directories(
    ntdllp
    PRIVATE
	${CMAKE_CURRENT_BINARY_DIR}
	${CMAKE_CURRENT_LIST_DIR}/inc
)
