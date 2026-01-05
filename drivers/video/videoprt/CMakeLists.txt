project(videoprt C)

file(GLOB SRC *.c)

add_driver(videoprt ${SRC} videoprt.rc)
target_link_libraries(videoprt PRIVATE lnxdrv)
