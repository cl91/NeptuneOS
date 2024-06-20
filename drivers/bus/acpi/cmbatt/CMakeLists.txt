project(cmbatt C)

list(APPEND SRC
    cmbatt.c
    cmexec.c
    cmbpnp.c
    cmbwmi.c
    guid.c
    cmbatt.rc)

add_driver(cmbatt ${SRC})
add_dependencies(cmbatt wmilib battc)
target_link_libraries(cmbatt PRIVATE wmilib battc)
