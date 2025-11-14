project(mountmgr C ASM)

list(APPEND SOURCE
    database.c
    device.c
    mountmgr.c
    notify.c
    point.c
    symlink.c
    uniqueid.c
    mntmgr.h)

add_driver(mountmgr ${SOURCE} mountmgr.rc)
target_link_libraries(mountmgr wdmguid)
