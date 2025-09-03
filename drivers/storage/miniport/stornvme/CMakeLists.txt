project(stornvme C ASM)

file(GLOB SOURCE *.c *.h)

add_driver(stornvme ${SOURCE} stornvme.rc)
target_link_libraries(stornvme PRIVATE storport)

target_compile_definitions(stornvme PUBLIC
    NTDDI_WIN7=0x06000000
    NTDDI_VERSION=0x06020000) # NTDDI_WIN8
