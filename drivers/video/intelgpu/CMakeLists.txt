project(intelgpu C)

file(GLOB SRC *.c)

add_driver(intelgpu ${SRC} intelgpu.rc)
target_link_libraries(intelgpu PRIVATE videoprt)
