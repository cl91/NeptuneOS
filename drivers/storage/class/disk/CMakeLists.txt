project(disk C ASM)

list(APPEND SOURCE
    data.c
    disk.c
    diskwmi.c
    geometry.c
    pnp.c
    disk.h)

add_driver(disk ${SOURCE} disk.rc)

target_compile_definitions(disk PUBLIC
    DEBUG_USE_KDPRINT
    _WIN32_WINNT=0x602
    NTDDI_VERSION=0x06020000) # NTDDI_WIN8

target_compile_options(disk PRIVATE
    -Wno-format -Wno-pointer-sign -Wno-pointer-to-int-cast -Wno-switch
    -Wno-unused-but-set-variable -Wno-gnu-variable-sized-type-not-at-end)

target_link_libraries(disk wdmguid classpnp)
