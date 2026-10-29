project(csrsrv C)

list(APPEND SOURCE
    src/api.c
    src/init.c
    src/procsup.c
    src/server.c
    src/session.c
    src/thredsup.c
    src/wait.c
    src/srv.h)

add_library(csrsrv SHARED
    ${SOURCE}
    csrsrv.rc)

target_include_directories(csrsrv PUBLIC ../../inc/csr inc
				  ../../../../base/sm/inc ../../../../base/sm/smlib/inc)
set_module_type(csrsrv native)
target_link_directories(csrsrv PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/../../..)
target_link_libraries(csrsrv smlib)
spec2def(csrsrv csrsrv.spec ${Arch})
set_dll_def(csrsrv csrsrv.def)
