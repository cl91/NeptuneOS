cmake_minimum_required(VERSION 3.12.0)

set(CMAKE_SYSTEM_NAME Linux)

project(ntlnxshim C ASM)

list(APPEND CMAKE_MODULE_PATH
    ${CMAKE_CURRENT_LIST_DIR}/../rtl)

add_compile_options(
    -Wall
    -nostdinc
    -fno-pic
    -fno-pie
    -Wno-incompatible-library-redeclaration
    --target=${TRIPLE}
    -DGIT_HEAD_SHA_SHORT=\"${GIT_HEAD_SHA_SHORT}\"
    -D_NTDLL_
    -D_NTSYSTEM_
)
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -D_DEBUG -DDBG=1" CACHE STRING "" FORCE)
set(CMAKE_C_FLAGS_MINSIZEREL "-Os -DNDEBUG" CACHE STRING "" FORCE)
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG" CACHE STRING "" FORCE)
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g -DNDEBUG" CACHE STRING "" FORCE)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-stack-protector")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -nostdinc++")
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_LIBRARIES "" CACHE STRING "" FORCE)
set(CMAKE_CXX_STANDARD_LIBRARIES "" CACHE STRING "" FORCE)

if(Arch STREQUAL "i386")
    set(KernelArch "x86")
    set(KernelWordSize 32)
elseif(Arch STREQUAL "amd64")
    set(KernelArch "x86")
    set(KernelWordSize 64)
elseif(Arch STREQUAL "arm64")
    set(KernelArch "arm")
    set(KernelWordSize 64)
else()
    message(FATAL_ERROR "Unsupported architecture: ${Arch}")
endif()

find_package(rtl REQUIRED)
rtl_import_project()
link_libraries(rtl)

include_directories(
    ${STRUCTURES_GEN_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    inc
    ${SANITIZED_SEL4_INCLUDE_DIR}
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
    ../../public/ndk/inc
    ../../public/crt/inc
    ../../public/crt/inc/${Arch}
)

list(APPEND COMMON_SRC
    ../ntdll/src/ke/services.c
    ../ntdll/src/rtl/debug.c
    src/${Arch}/entry.S
    src/init.c
    src/except.c
)

list(APPEND KRNL_SRC
    ${COMMON_SRC}
    ../wdm/src/wdmsvc.c
    src/krnl.c
)

list(APPEND USER_SRC
    ${COMMON_SRC}
)

add_library(ntlnxshimk STATIC ${KRNL_SRC})
add_library(ntlnxshimu STATIC ${USER_SRC})
add_dependencies(ntlnxshimk rtl)
add_dependencies(ntlnxshimu rtl)
target_compile_options(ntlnxshimk PRIVATE -DKRNLMODE -D_NTDDK_)
