cmake_minimum_required(VERSION 3.12.0)

set(CMAKE_SYSTEM_NAME Windows)

project(drivers)

add_compile_options(
    -Wall
    -nostdinc
    -fno-pic
    -fno-pie
    -Wno-incompatible-library-redeclaration
    -msoft-float
    -mno-sse
    -mno-mmx
    -fasync-exceptions
    --target=${TRIPLE}
    -DGIT_HEAD_SHA_SHORT=\"${GIT_HEAD_SHA_SHORT}\"
)

include_directories(
    ${CMAKE_CURRENT_LIST_DIR}/../public/crt/inc
    ${CMAKE_CURRENT_LIST_DIR}/../public/ndk/inc
    ${CMAKE_CURRENT_LIST_DIR}/../public/ddk/inc
)

link_directories(${NDK_LIB_PATH})
link_directories(${DDK_LIB_PATH})

set(CMAKE_C_FLAGS_DEBUG "-g -Xclang -gcodeview -O0 -D_DEBUG -DDBG")
set(CMAKE_C_FLAGS_MINSIZEREL "-Os -DNDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g -DNDEBUG -Xclang -gcodeview")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-stack-protector -ftls-model=global-dynamic")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -nostdinc++")
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_LIBRARIES "-lntdll -lwdm")
set(CMAKE_CXX_STANDARD_LIBRARIES "-lntdll -lwdm")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} --target=${TRIPLE} -fuse-ld=lld-link -nostdlib -Wl,-subsystem:native -Wl,-entry:DriverEntry -Wl,-errorlimit:0")

include(${CMAKE_CURRENT_LIST_DIR}/../tools/cmake/spec2def.cmake)

function(add_driver _name _src)
    add_library(${_name} SHARED ${_src} ${ARGN})
    set_target_properties(${_name} PROPERTIES SUFFIX ".sys")
endfunction()

add_subdirectory(lib)
add_subdirectory(base)
add_subdirectory(input)
add_subdirectory(storage)
