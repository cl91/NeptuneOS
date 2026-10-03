project(kernel32 C)

add_definitions(-D_KERNEL32_)
include_directories(inc)

list(APPEND SOURCE
    src/actctx.c
    src/appcache.c
    src/atom.c
    src/atomansi.c
    src/compname.c
    src/debugger.c
    src/dep.c
    src/dosdev.c
    src/dllmain.c
    src/environ.c
    src/except.c
    src/fiber.c
    src/handle.c
    src/heapmem.c
    src/job.c
    src/loader.c
    src/path.c
    src/pathansi.c
    src/perfcnt.c
    src/power.c
    src/proc.c
    src/procansi.c
    src/resntfy.c
    src/session.c
    src/synch.c
    src/synchansi.c
    src/sysinfo.c
    src/sysinfoansi.c
    src/time.c
    src/timerqueue.c
    src/toolhelp.c
    src/utils.c
    src/thread.c
    src/vdm.c
    src/version.c
    src/versionansi.c
    src/virtmem.c
    src/console/alias.c
    src/console/console.c
    src/console/history.c
    src/console/init.c
    src/console/readwrite.c
    src/file/backup.c
    src/file/cnotify.c
    src/file/copy.c
    src/file/copyansi.c
    src/file/create.c
    src/file/delete.c
    src/file/deviceio.c
    src/file/dir.c
    src/file/diransi.c
    src/file/disk.c
    src/file/fileinfo.c
    src/file/fileinfoansi.c
    src/file/filemap.c
    src/file/filename.c
    src/file/fileutils.c
    src/file/find.c
    src/file/hardlink.c
    src/file/iocompl.c
    src/file/lfile.c
    src/file/lock.c
    src/file/mailslot.c
    src/file/move.c
    src/file/moveansi.c
    src/file/mntpoint.c
    src/file/mntpointansi.c
    src/file/npipe.c
    src/file/rw.c
    src/file/tape.c
    src/file/volume.c
    src/file/volumeansi.c
    src/shared_utils.c
    wine/actctx.c
    wine/comm.c
    wine/lzexpand.c
    wine/muldiv.c
    wine/profile.c
    wine/res.c
    wine/timezone.c
    winnls/string/casemap.c
    winnls/string/collation.c
    winnls/string/digitmap.c
    winnls/string/fold.c
    winnls/string/format_msg.c
    winnls/string/japanese.c
    winnls/string/locale.c
    winnls/string/localeansi.c
    winnls/string/lcformat.c
    winnls/string/lcformatansi.c
    winnls/string/lstring.c
    winnls/string/nls.c
    winnls/string/sortkey.c)

list(APPEND NT6_SOURCE
    src/console/vista.c
    nt6/EnumSystemLocalesEx.c
    nt6/firmware.c
    nt6/GetLocaleInfoEx.c
    nt6/GetFileInformationByHandleEx.c
    nt6/GetFinalPathNameByHandle.c
    nt6/GetNamedPipeClientProcessId.c
    nt6/GetSystemDefaultLocaleName.c
    nt6/GetTickCount64.c
    nt6/GetUserDefaultLocaleName.c
    nt6/InitOnce.c
    nt6/IsValidLocaleName.c
    nt6/LCIDToLocaleName.c
    nt6/LocaleNameToLCID.c
    nt6/sync.c
    nt6/ThreadDescription.c
    nt6/threadpool.c
    nt6/vista.c)

if(ARCH STREQUAL "i386")
    list(APPEND ASM_SOURCE
        src/i386/fiber.S
        src/i386/thread.S)
elseif(ARCH STREQUAL "amd64")
    list(APPEND ASM_SOURCE
        src/amd64/fiber.S)
elseif(ARCH STREQUAL "arm64")
    list(APPEND ASM_SOURCE
        src/arm64/fiber.S
        src/arm64/thread.S)
endif()

add_library(kernel32 MODULE
    ${SOURCE}
    ${NT6_SOURCE}
    ${ASM_SOURCE}
    kernel32.rc)

target_include_directories(kernel32 PRIVATE ../../inc)
set_module_type(kernel32 basedll)
spec2def(kernel32 kernel32.spec ${Arch})
set_dll_def(kernel32 kernel32.def)
