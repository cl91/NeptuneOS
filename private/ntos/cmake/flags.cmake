cmake_minimum_required(VERSION 3.7.2)

# Setup base flags as defined by the kernel before including the rest
include(${KERNEL_FLAGS_PATH})

if((${CMAKE_BUILD_TYPE} STREQUAL "Release") OR (${CMAKE_BUILD_TYPE} STREQUAL "MinSizeRel"))
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

# The NT Executive task and all device driver tasks cannot use FPU registers,
# since we do not handle FPU context saving when switching threads.
# TODO: Profile +fpu vs -fpu context switching cost.
add_compile_options(
    -nostdinc
    -fno-pic
    -fno-pie
    -fno-stack-protector
    -fno-asynchronous-unwind-tables
    -ftls-model=local-exec
    -mtls-direct-seg-refs
    -Wno-incompatible-library-redeclaration
    -msoft-float
    -mno-sse
    -mno-mmx
    -DGIT_HEAD_SHA_SHORT=\"${GIT_HEAD_SHA_SHORT}\"
    -D_NTOSKRNL_
)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -nostdinc++")
set(CMAKE_C_STANDARD 11)
set(LinkPageSize "0x1000" CACHE STRING "Page size to be used for linker")
mark_as_advanced(LinkPageSize)
set(
    CMAKE_EXE_LINKER_FLAGS
    "${CMAKE_EXE_LINKER_FLAGS} -static -nostdlib -z max-page-size=${LinkPageSize}"
)

if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
    add_compile_options(-fuse-ld=lld)
    target_compile_options(kernel.elf PRIVATE "-Wno-error=uninitialized")
    target_compile_options(kernel.elf PRIVATE "-Wno-error=shift-negative-value")
    set(CMAKE_AR "llvm-ar" CACHE FILEPATH "Archiver")
endif()
