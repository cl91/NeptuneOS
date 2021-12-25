# Common runtime library linked by both ntos and ntdll

cmake_minimum_required(VERSION 3.12.0)

project(rtl C)

file(GLOB SRC ${CMAKE_CURRENT_LIST_DIR}/src/*.c ${CMAKE_CURRENT_LIST_DIR}/src/*/*/*.c ${CMAKE_CURRENT_LIST_DIR}/src/*/*/${Arch}/*.c ${CMAKE_CURRENT_LIST_DIR}/src/*/*/${Arch}/*.S)
add_library(rtl STATIC ${SRC})
target_include_directories(
    rtl
    PUBLIC
	../../public/ndk/inc
	../../public/crt/inc
	../../public/crt/inc/${Arch}
	inc
	inc/${Arch}
	${CMAKE_CURRENT_BINARY_DIR}
    PRIVATE
	src/inc
	src/inc/${Arch}
	${STRUCTURES_GEN_DIR}
	../../sel4/libsel4/include
	../../sel4/libsel4/mode_include/${KernelWordSize}
	../../sel4/libsel4/sel4_plat_include/${KernelPlatform}
	../../sel4/libsel4/arch_include/${KernelArch}
	../../sel4/libsel4/sel4_arch_include/${KernelSel4Arch}
	${SEL4_GENERATED_HEADERS_DIR}/kernel/gen_config
	${SEL4_GENERATED_HEADERS_DIR}/libsel4/gen_config
	${SEL4_GENERATED_HEADERS_DIR}/libsel4/autoconf
	${SEL4_GENERATED_HEADERS_DIR}/libsel4/include
	${SEL4_GENERATED_HEADERS_DIR}/libsel4/arch_include/${KernelArch}
	${SEL4_GENERATED_HEADERS_DIR}/libsel4/sel4_arch_include/${KernelSel4Arch}
)

add_custom_target(
    syssvc_gen_h ALL
    COMMAND python ${CMAKE_CURRENT_LIST_DIR}/syssvc-gen.py --syssvc_xml ${CMAKE_CURRENT_LIST_DIR}/syssvc.xml --wdmsvc_xml ${CMAKE_CURRENT_LIST_DIR}/wdmsvc.xml --out_dir ${CMAKE_CURRENT_BINARY_DIR}
    VERBATIM
)
add_dependencies(rtl syssvc_gen_h)
