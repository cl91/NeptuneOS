project(wmilib C)

list(APPEND SOURCE
    wmilib.c)

add_library(wmilib STATIC ${SOURCE})
