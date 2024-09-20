project(storahci C ASM)

file(GLOB SOURCE *.c *.h)

add_driver(storahci ${SOURCE} storahci.rc)
