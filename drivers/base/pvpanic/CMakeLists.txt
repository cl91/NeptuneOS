project(pvpanic C)

file(GLOB SRC *.c)

add_driver(pvpanic ${SRC} pvpanic.rc)
target_link_libraries(pvpanic PRIVATE lnxdrv)
