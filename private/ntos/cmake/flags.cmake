cmake_minimum_required(VERSION 3.7.2)

# Setup base flags as defined by the kernel before including the rest
include(${KERNEL_FLAGS_PATH})

if ("${CMAKE_BUILD_TYPE}" MATCHES "^(Release|MinSizeRel)$")
    option(UserLinkerGCSections "Perform dead code and data removal
        Build user level with -ffunction-sections and -fdata-sections and
        link with --gc-sections. The first two options place each function
        and data in a different section such that --gc-sections is able
        to effectively discard sections that are unused after a reachability
        analysis. This does not interact well with debug symbols generated
        by -g and can in some cases result in larger object files and binaries" ON)

    if(UserLinkerGCSections)
        add_compile_options(-ffunction-sections -fdata-sections)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections ")
    endif()
endif()
mark_as_advanced(UserLinkerGCSections)

add_compile_options(
    -Wall
    -nostdinc
    -fno-pic
    -fno-pie
    -fno-stack-protector
    -fno-asynchronous-unwind-tables
    -ftls-model=local-exec
    -Wno-incompatible-library-redeclaration
    -DGIT_HEAD_SHA_SHORT=\"${GIT_HEAD_SHA_SHORT}\"
    -D_NTOSKRNL_
)
# For i386 and amd64, we disable FPU-related codegen for the NT Executive task in order
# to eliminate the overhead introduced by saving and restoring the FPU registers.
# TODO: Profile +fpu vs -fpu context switching cost.
if ("${Arch}" MATCHES "^(i386|amd64)$")
add_compile_options(
    -mtls-direct-seg-refs
    -msoft-float
    -mno-sse
    -mno-mmx
)
endif()

# This prevents the i386 target from generating the popcnt instructions since
# this isn't added until Nehalem (Core i7 first gen)
if(Arch STREQUAL "i386")
    add_compile_options(-march=i686)
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -nostdinc++")
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -D_DEBUG -DDBG=1" CACHE STRING "" FORCE)
set(CMAKE_C_FLAGS_MINSIZEREL "-Os -DNDEBUG" CACHE STRING "" FORCE)
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG" CACHE STRING "" FORCE)
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g -DNDEBUG" CACHE STRING "" FORCE)
set(LinkPageSize "0x1000" CACHE STRING "Page size to be used for linker")
mark_as_advanced(LinkPageSize)
set(
    CMAKE_EXE_LINKER_FLAGS
    "${CMAKE_EXE_LINKER_FLAGS} -static -nostdlib -z max-page-size=${LinkPageSize}"
)

if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
    target_compile_options(kernel.elf PRIVATE "-Wno-error=uninitialized")
    target_compile_options(kernel.elf PRIVATE "-Wno-error=shift-negative-value")
    set(CMAKE_AR "llvm-ar" CACHE FILEPATH "Archiver")
endif()
