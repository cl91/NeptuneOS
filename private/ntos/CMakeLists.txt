cmake_minimum_required(VERSION 3.12.0)

project(ntos C)

list(APPEND CMAKE_MODULE_PATH
    ${CMAKE_CURRENT_LIST_DIR}/../rtl)

file(GLOB SRC ${CMAKE_CURRENT_LIST_DIR}/src/*/*.c ${CMAKE_CURRENT_LIST_DIR}/src/*/${Arch}/*.c ${CMAKE_CURRENT_LIST_DIR}/src/*/${Arch}/*.s)
add_library(ntos STATIC ${SRC})
add_dependencies(ntos rtl)
target_link_libraries(ntos PRIVATE rtl)
target_include_directories(
    ntos
    PUBLIC
        inc
	inc/${Arch}
	../../public/sdk/inc
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
