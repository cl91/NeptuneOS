project(pci C)

include_directories(${CMAKE_CURRENT_BINARY_DIR})

list(APPEND SOURCE
    id.c
    pcibridge.c
    cardbus.c
    state.c
    debug.c
    device.c
    dispatch.c
    fdo.c
    init.c
    pdo.c
    power.c
    utils.c
    guid.c
    pci.rc)

add_message_headers(UNICODE pciclass.mc)
add_driver(pci ${SOURCE})
add_dependencies(pci pciclass)
