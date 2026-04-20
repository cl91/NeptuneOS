#include <arm64asm.h>
#include <ksarm64.h>

.PROC LdrInitializeThunk
    /* The server pushes the first two parameters into the stack
     * before dispatching to this entry point. */
    ldp x0, x1, [sp]
    cmp x1, xzr
    bne KiUserExceptionDispatcher
    b LdrpInitialize
.ENDP

.PROC KiUserExceptionDispatcher
    .seh_stackalloc 0x10
    .seh_pushframe
    .seh_endprologue
    bl RtlpSaveFpuContext
    b KiDispatchUserException
.ENDP
