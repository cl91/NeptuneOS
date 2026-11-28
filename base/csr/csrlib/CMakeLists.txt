project(csrlib C)

add_definitions(-D_NTSYSTEM_)

list(APPEND SOURCE
    api.c
    capture.c
    connect.c
    csrdll.rc)

add_library(csrdll SHARED ${SOURCE})
spec2def(csrdll csrdll.spec ${Arch})
set_dll_def(csrdll csrdll.def)
