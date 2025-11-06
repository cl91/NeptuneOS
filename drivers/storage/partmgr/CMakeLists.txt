project(partmgr C ASM)

list(APPEND SOURCE
    partition.c
    partmgr.c
    utils.c
    guid.c)

add_driver(partmgr ${SOURCE} partmgr.rc)
