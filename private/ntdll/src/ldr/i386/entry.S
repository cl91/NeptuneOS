#include <ks386.h>

.section .text
.global _LdrInitializeThunk
_LdrInitializeThunk:
    /*
     * This entry point serves both as the initial entry point for a
     * thread and as the entry point for an exception. The latter case
     * is distinguished by the second parameter being non-zero.
     */
    test %edx, %edx
    jnz KiUserExceptionDispatcher

    /* If we got here, we are being called as the initial entry point of
     * a new thread. In this case %ecx contains the address of the TEB */
    call @LdrpInitialize@4

    /* Should not return. */
1:  jmp  1b

KiUserExceptionDispatcher:
    /* Capture the floating point context. The server does not modify any
     * FPU state when dispatching exceptions, so what we capture here is
     * what the program sees when the exception happens. */
    mov %ecx, %eax
    mov %edx, %ecx
    /* RtlpSaveFpuContext does not modify any registers, so there is no need
     * to save any registers other than rcx */
    call @RtlpSaveFpuContext@4
    mov %eax, %ecx
    call @KiDispatchUserException@8
    /* Should not return. */
1:  jmp 1b

/* Must match offset of ThreadLocalStoragePointer in TEB struct */
.global __tls_array
.equ __tls_array, TbThreadLocalStoragePointer
