project(lnxdrv C)

add_compile_options(-DLNXDRV_SYS)

file(GLOB SRC src/*.c)

add_driver(lnxdrv ${SRC} lnxdrv.rc)
target_include_directories(lnxdrv PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/inc)

spec2def(lnxdrv lnxdrv.spec ${Arch})
set_dll_def(lnxdrv lnxdrv.def)
