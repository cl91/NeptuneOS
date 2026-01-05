project(usbhci C)

file(GLOB SRC *.c)

add_driver(usbhci ${SRC} usbhci.rc)
target_link_libraries(usbhci PRIVATE lnxdrv)
