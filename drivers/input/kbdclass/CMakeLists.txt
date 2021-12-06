project(kbdclass C)

file(GLOB SRC *.c)

add_driver(kbdclass ${SRC})
