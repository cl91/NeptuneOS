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
    jnz _KiUserExceptionDispatcher

    /* If we got here, we are being called as the initial entry point of
     * a new thread. In this case %ecx contains the address of the TEB */
    call @LdrpInitialize@4

    /* Should not return. */
1:  jmp  1b

.global _KiUserExceptionDispatcher
_KiUserExceptionDispatcher:
    call @KiDispatchUserException@8
    /* Should not return. */
1:  jmp 1b

/* Must match offset of ThreadLocalStoragePointer in TEB struct */
.global __tls_array
.equ __tls_array, TbThreadLocalStoragePointer
