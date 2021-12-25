project(i8042prt C)

include_directories(../../lib/dmilib)

file(GLOB SRC *.c)

add_driver(i8042prt ${SRC})
target_link_libraries(i8042prt dmilib)
