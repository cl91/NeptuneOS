#include <ks386.h>

.section .text
.global _LdrInitializeThunk
_LdrInitializeThunk:
    /*
     * The virtual address of the IPC buffer is in %ecx
     * The system dll tls region address is in %edx
     */
    call @LdrpInitialize@8

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
