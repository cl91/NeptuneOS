project(pci C)

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
target_include_directories(pci PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
