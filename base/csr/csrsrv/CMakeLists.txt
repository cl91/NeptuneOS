project(csrsrv C)

add_definitions(-D_NTSYSTEM_)

list(APPEND SOURCE
    api.c
    init.c
    procsup.c
    server.c
    thredsup.c
    srv.h)

add_library(csrsrv SHARED
    ${SOURCE}
    csrsrv.rc)

target_link_libraries(csrsrv smdll)
spec2def(csrsrv csrsrv.spec ${Arch})
set_dll_def(csrsrv csrsrv.def)
