project(smlib C)

add_definitions(-D_NTSYSTEM_)

list(APPEND SOURCE
    src/smclient.c
    src/smutils.c)

add_library(smdll SHARED ${SOURCE})
target_include_directories(smdll PUBLIC ../inc inc)
spec2def(smdll smdll.spec ${Arch})
set_dll_def(smdll smdll.def)
