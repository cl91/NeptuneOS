#include <ks386.h>

.section .text
.global _LdrInitializeThunk
_LdrInitializeThunk:
    mov %esp, %ebp

    /*
     * GCC expects that a C function is always entered via a call
     * instruction and that the stack is 16-byte aligned before such an
     * instruction (leaving it 16-byte aligned + 1 word from the
     * implicit push when the function is entered).
     *
     * If additional items are pushed onto the stack, the stack must be
     * manually re-aligned before pushing the arguments for the
     * call instruction to LdrpInitialize.
     */
    sub  $0x8, %esp
    push %ebp

    /*
     * The virtual address of the IPC buffer is in %ecx
     * The system dll tls region address is in %edx
     * Thread entry point is in %eax
     */
    push %eax
    call @LdrpInitialize@12

    /* Should not return. */
1:
    jmp  1b

/* Must match offset of ThreadLocalStoragePointer in TEB struct */
.global __tls_array
.equ __tls_array, TbThreadLocalStoragePointer
