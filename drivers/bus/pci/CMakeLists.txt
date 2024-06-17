project(pci C)

list(APPEND SOURCE
    busnum.c
    config.c
    devhere.c
    id.c
    pcibridge.c
    romimage.c
    state.c
    debug.c
    device.c
    dispatch.c
    enum.c
    fdo.c
    hookhal.c
    init.c
    pdo.c
    power.c
    usage.c
    utils.c
    guid.c)

add_driver(pci ${SOURCE})
