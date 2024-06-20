project(pci C)

include_directories(${CMAKE_CURRENT_BINARY_DIR})

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
    guid.c
    pci.rc)

add_message_headers(UNICODE pciclass.mc)
add_driver(pci ${SOURCE})
add_dependencies(pci pciclass)
