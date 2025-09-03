project(storport C ASM)

list(APPEND SOURCE
    fdo.c
    miniport.c
    misc.c
    pdo.c
    storport.c
    wmi.c
    guid.c)

add_driver(storport ${SOURCE} storport.rc)

spec2def(storport storport.spec ${Arch})
set_dll_def(storport storport.def)
