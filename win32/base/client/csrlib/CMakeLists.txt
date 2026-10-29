project(csrlib C)

add_definitions(-D_NTSYSTEM_)

list(APPEND SOURCE
    src/api.c
    src/capture.c
    src/connect.c
    csrdll.rc)

add_library(csrdll SHARED ${SOURCE})
target_include_directories(csrdll PUBLIC ../../inc inc PRIVATE)
set_module_type(csrdll native)
spec2def(csrdll csrdll.spec ${Arch})
set_dll_def(csrdll csrdll.def)