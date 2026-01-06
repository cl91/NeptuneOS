cmake_minimum_required(VERSION 3.12.0)

set(CMAKE_SYSTEM_NAME Linux)

project(eth C ASM)

add_compile_options(
    -Wall
    -nostdinc
    -fno-pic
    -fno-pie
    -Wno-incompatible-library-redeclaration
    --target=${TRIPLE}
    -DGIT_HEAD_SHA_SHORT=\"${GIT_HEAD_SHA_SHORT}\"
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
set(CMAKE_EXE_LINKER_FLAGS "-static -nostdlib -fuse-ld=lld -Wl,--entry=LnxDriverEntry -Wl,--image-base,0x18000000")
set(CMAKE_EXECUTABLE_SUFFIX ".xdrv")

include_directories(
    inc
    ../../public/ndk/inc
    ../../public/crt/inc
    ../../public/crt/inc/${Arch}
    ../../public/ldk/inc
)

file(GLOB SRC *.[cS] ${Arch}/*.[cS])

add_executable(eth ${SRC})
