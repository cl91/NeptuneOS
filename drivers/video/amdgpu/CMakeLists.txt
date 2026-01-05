project(amdgpu C)

file(GLOB SRC *.c)

add_driver(amdgpu ${SRC} amdgpu.rc)
target_link_libraries(amdgpu PRIVATE videoprt)
