project(stornvme C ASM)

file(GLOB SOURCE *.c *.h)

add_driver(stornvme ${SOURCE} stornvme.rc)
target_link_libraries(stornvme PRIVATE storport)
