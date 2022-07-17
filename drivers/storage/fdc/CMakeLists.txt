project(fdc C)

file(GLOB SRC *.c)

add_driver(fdc ${SRC})
