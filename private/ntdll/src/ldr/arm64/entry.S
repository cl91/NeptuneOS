#include <arm64asm.h>
#include <ksarm64.h>

.PROC LdrInitializeThunk
    cmp x2, xzr
    bne KiUserExceptionDispatcher
    b LdrpInitialize
.ENDP

.PROC KiUserExceptionDispatcher
    ldp x2, x3, [x1, CONTEXT_SP]
    stp x2, x3, [sp, -0x10]!
    .seh_stackalloc 0x10
    .seh_pushframe
    .seh_endprologue
    mov x2, x30
    bl RtlpSaveFpuContext
    mov x30, x2
    b KiDispatchUserException
.ENDP
