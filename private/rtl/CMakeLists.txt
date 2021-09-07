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
)

add_custom_target(
    syssvc_gen_h ALL
    COMMAND python ${CMAKE_CURRENT_LIST_DIR}/syssvc-gen.py --syssvc_xml ${CMAKE_CURRENT_LIST_DIR}/syssvc.xml --out_dir ${CMAKE_CURRENT_BINARY_DIR}
    VERBATIM
)
add_dependencies(rtl syssvc_gen_h)
