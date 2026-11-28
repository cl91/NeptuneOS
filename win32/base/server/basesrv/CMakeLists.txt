project(basesrv C)

list(APPEND SOURCE
    appcompat.c
    dosdev.c
    init.c
    proc.c
    sndsntry.c
    nls.c
    basesrv.h)

add_library(basesrv SHARED
    ${SOURCE}
    basesrv.rc)

set_module_type(basesrv native)
target_include_directories(basesrv PUBLIC ../../inc)
target_link_libraries(basesrv csrsrv)
spec2def(basesrv basesrv.spec ${Arch})
set_dll_def(basesrv basesrv.def)
