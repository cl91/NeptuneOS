project(pnp C)

file(GLOB SRC *.c)

add_driver(pnp ${SRC})
