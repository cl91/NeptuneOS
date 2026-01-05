project(ethernet C)

file(GLOB SRC *.c)

add_driver(ethernet ${SRC} ethernet.rc)
target_link_libraries(ethernet PRIVATE lnxdrv)
