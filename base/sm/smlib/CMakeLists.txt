project(smlib C)

add_definitions(-D_NTSYSTEM_)

list(APPEND SOURCE
    smclient.c
    smutils.c)

add_library(smdll SHARED ${SOURCE})
spec2def(smdll smdll.spec ${Arch})
set_dll_def(smdll smdll.def)
