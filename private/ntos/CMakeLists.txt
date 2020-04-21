cmake_minimum_required(VERSION 3.12.0)

project(ntos C)

file(GLOB SRC ${CMAKE_CURRENT_LIST_DIR}/src/*/*.c ${CMAKE_CURRENT_LIST_DIR}/src/rtl/crt/*.c ${CMAKE_CURRENT_LIST_DIR}/src/*/${Arch}/*.c ${CMAKE_CURRENT_LIST_DIR}/src/*/${Arch}/*.s)
add_library(ntos STATIC ${SRC})
target_include_directories(
    ntos
    PUBLIC
        inc
	inc/${Arch}
	../../public/sdk/inc
	../../public/crt/inc
	../../public/crt/inc/${Arch}
	../../sel4/libsel4/include
	../../sel4/libsel4/mode_include/${KernelWordSize}
	../../sel4/libsel4/sel4_plat_include/${KernelPlatform}
	../../sel4/libsel4/arch_include/${KernelArch}
	../../sel4/libsel4/sel4_arch_include/${KernelSel4Arch}
	../../build/elf/kernel/gen_config
	../../build/elf/libsel4/gen_config
	../../build/elf/libsel4/autoconf
	../../build/elf/libsel4/include
	../../build/elf/libsel4/arch_include/${KernelArch}
	../../build/elf/libsel4/sel4_arch_include/${KernelSel4Arch}
    PRIVATE
        src/inc
	src/inc/${Arch}
)
