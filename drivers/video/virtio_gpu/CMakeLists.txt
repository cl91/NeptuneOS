project(virtio_gpu C)

file(GLOB SRC *.c)

add_driver(virtio_gpu ${SRC} virtio_gpu.rc)
target_link_libraries(virtio_gpu PRIVATE videoprt)
