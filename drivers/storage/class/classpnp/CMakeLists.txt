project(classpnp C ASM)

list(APPEND SOURCE
    autorun.c
    class.c
    classwmi.c
    clntirp.c
    create.c
    data.c
    debug.c
    dictlib.c
    dispatch.c
    guid.c
    history.c
    lock.c
    obsolete.c
    power.c
    retry.c
    srblib.c
    utils.c
    xferpkt.c)

add_driver(classpnp
    ${SOURCE}
    class.rc)

spec2def(classpnp classpnp.spec ${Arch})
set_dll_def(classpnp classpnp.def)

target_compile_definitions(classpnp PUBLIC
    DEBUG_USE_KDPRINT
    _WIN32_WINNT=0x602
    NTDDI_VERSION=0x06020000) # NTDDI_WIN8

target_compile_definitions(classpnp PRIVATE
    _CLASSPNP_=1
    CLASS_GLOBAL_BREAK_ON_LOST_IRPS=0
    CLASS_GLOBAL_SECONDS_TO_WAIT_FOR_SYNCHRONOUS_SRB=100
    CLASS_GLOBAL_USE_DELAYED_RETRY=1
    CLASS_GLOBAL_BUFFERED_DEBUG_PRINT=0
    CLASS_GLOBAL_BUFFERED_DEBUG_PRINT_BUFFER_SIZE=512
    CLASS_GLOBAL_BUFFERED_DEBUG_PRINT_BUFFERS=512)

target_compile_options(classpnp PRIVATE
    -Wno-pointer-to-int-cast -Wno-switch -Wno-unused-but-set-variable
    -Wno-gnu-variable-sized-type-not-at-end)
