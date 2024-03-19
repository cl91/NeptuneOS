cmake_minimum_required(VERSION 3.7.2)

project(base)

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_EXECUTABLE_SUFFIX ".exe")
set(CMAKE_SHARED_LIBRARY_SUFFIX ".dll")

add_compile_options(
    -Wall
    -nostdinc
    -fno-pic
    -fno-pie
    -Wno-incompatible-library-redeclaration
    -fasync-exceptions
    --target=${TRIPLE}
    -DGIT_HEAD_SHA_SHORT=\"${GIT_HEAD_SHA_SHORT}\"
)

include_directories(
    ${CMAKE_CURRENT_LIST_DIR}/../public/crt/inc
    ${CMAKE_CURRENT_LIST_DIR}/../public/ndk/inc
)

link_directories(${NDK_LIB_PATH})

set(CMAKE_C_FLAGS_DEBUG "-g -Xclang -gcodeview -O0 -D_DEBUG")
set(CMAKE_C_FLAGS_MINSIZEREL "-Os -DNDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g -DNDEBUG -Xclang -gcodeview")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-stack-protector -ftls-model=global-dynamic")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -nostdinc++")
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_LIBRARIES "-lntdll -lntdllp")
set(CMAKE_CXX_STANDARD_LIBRARIES "-lntdll -lntdllp")
set(NATIVE_LINKER_FLAGS "--target=${TRIPLE} -fuse-ld=lld-link -nostdlib -Wl,-subsystem:native -Wl,-safeseh:no -Wl,-errorlimit:0")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${NATIVE_LINKER_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${NATIVE_LINKER_FLAGS} -Wl,-entry:NtProcessStartup")

include(${CMAKE_CURRENT_LIST_DIR}/../tools/cmake/spec2def.cmake)

add_subdirectory(smss)
add_subdirectory(ntcmd)
