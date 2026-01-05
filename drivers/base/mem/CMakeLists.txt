project(mem C)

file(GLOB SRC *.c)

add_driver(mem ${SRC} mem.rc)
target_link_libraries(mem PRIVATE lnxdrv)
