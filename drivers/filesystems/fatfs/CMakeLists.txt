project(fatfs C)

file(GLOB SRC *.c)

add_driver(fatfs ${SRC} fatfs.rc)
