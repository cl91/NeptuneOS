project(compbatt C)

list(APPEND SRC
    compbatt.c
    comppnp.c
    guid.c)

add_driver(compbatt ${SRC})
add_dependencies(compbatt wmilib battc)
target_link_libraries(compbatt PRIVATE wmilib battc)
