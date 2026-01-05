project(nvgpu C)

file(GLOB SRC *.c)

add_driver(nvgpu ${SRC} nvgpu.rc)
target_link_libraries(nvgpu PRIVATE videoprt)
