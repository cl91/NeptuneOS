project(beep C)

file(GLOB SRC *.c)

add_driver(beep ${SRC})
