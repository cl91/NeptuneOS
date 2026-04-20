#include <ks386.h>

.section .text
.global _LdrInitializeThunk
_LdrInitializeThunk:
    /* Make sure we start with a valid ebp */
    mov %esp, %ebp

    /*
     * This entry point serves both as the initial entry point for a
     * thread and as the entry point for an exception. The latter case
     * is distinguished by the second parameter being non-zero.
     */
    mov (%esp), %ecx
    mov 4(%esp), %edx
    test %edx, %edx
    jnz KiUserExceptionDispatcher

    /* If we got here, we are being called as the initial entry point of
     * a new thread. In this case %ecx contains the address of the TEB */
    call _LdrpInitialize

    /* Should not return. */
1:  jmp  1b

KiUserExceptionDispatcher:
    /* Capture the floating point context. The server does not modify any
     * FPU state when dispatching exceptions, so what we capture here is
     * what the program sees when the exception happens. */
    call @RtlpSaveFpuContext@4
    call _KiDispatchUserException
    /* Should not return. */
1:  jmp 1b
