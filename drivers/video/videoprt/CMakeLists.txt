project(videoprt C)

add_compile_options(-D_VIDEOPRT_)

file(GLOB SRC src/*.c)

add_driver(videoprt ${SRC} videoprt.rc)
target_include_directories(videoprt PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/inc)
target_link_libraries(videoprt PUBLIC lnxdrv)

spec2def(videoprt videoprt.spec ${Arch})
set_dll_def(videoprt videoprt.def)
