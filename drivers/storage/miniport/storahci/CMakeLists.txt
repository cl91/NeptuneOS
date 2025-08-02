project(storahci C ASM)

file(GLOB SOURCE *.c *.h)

add_driver(storahci ${SOURCE} storahci.rc)
target_link_libraries(storahci PRIVATE storport)
