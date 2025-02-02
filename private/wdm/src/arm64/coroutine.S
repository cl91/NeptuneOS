#include <wdmasm.h>
#include <arm64asm.h>

#define COROUTINE_START_PROLOGUE			;\
    /* KiCurrentCoroutineStackTop = StackTop (x0); */	;\
    adr x3, KiCurrentCoroutineStackTop			;\
    str x0, [x3]					;\
    /* Save all callee-saved (non-volatile) registers */;\
    stp x29, x30, [sp, -0x10]!				;\
    stp x27, x28, [sp, -0x10]!				;\
    stp x25, x26, [sp, -0x10]!				;\
    stp x23, x24, [sp, -0x10]!				;\
    stp x21, x22, [sp, -0x10]!				;\
    stp x19, x20, [sp, -0x10]!				;\
    /* Save the master thread stack pointer */		;\
    mov x3, sp						;\
    str x3, [x0, -0x20]					;\
    /* Save the address to KiExitCoroutine below so     ;\
     * KiYieldCoroutine knowns where to jump to */	;\
    adr x3, KiExitCoroutine				;\
    str x3, [x0, -0x18]

/*
 * NTSTATUS KiStartCoroutine(IN PVOID StackTop,                        // x0
 *                           IN KI_COROUTINE_ENTRYPOINT EntryPoint,    // x1
 *                           IN PVOID Context)                         // x2
 */
.PROC KiStartCoroutine
    COROUTINE_START_PROLOGUE
    /* Switch to the stack pointer given by StackTop (x0). */
    mov sp, x0
    /* Skip the KI_COROUTINE_STACK struct */
    sub sp, sp, 0x20
    /* Call the coroutine entry point */
    mov x0, x2
    blr x1
    /* Restore the old stack pointer. Note after the coroutine
     * is suspended and later resumed, this stack pointer refers
     * to the stack frame of KiResumeCoroutine rather than
     * KiStartCoroutine. */
    ldr x1, [sp]
    mov sp, x1
KiExitCoroutine:
    /* Restore all callee-saved (non-clobbered) registers.
     * Note this is where KiYieldCoroutine jumps to */
    ldp x19, x20, [sp], 0x10
    ldp x21, x22, [sp], 0x10
    ldp x23, x24, [sp], 0x10
    ldp x25, x26, [sp], 0x10
    ldp x27, x28, [sp], 0x10
    ldp x29, x30, [sp], 0x10
    /* KiCurrentCoroutineStackTop = NULL; */
    adr x3, KiCurrentCoroutineStackTop
    mov x1, xzr
    str x1, [x3]
    /* Branch to the address in lr */
    ret
.ENDP

/*
 * KiYieldCoroutine()
 */
.PROC KiYieldCoroutine
    /* Save all callee-saved (non-clobbered) registers */
    stp x29, x30, [sp, -0x10]!
    stp x27, x28, [sp, -0x10]!
    stp x25, x26, [sp, -0x10]!
    stp x23, x24, [sp, -0x10]!
    stp x21, x22, [sp, -0x10]!
    stp x19, x20, [sp, -0x10]!
    /* Load the current coroutine stack top to x1 */
    adr x1, KiCurrentCoroutineStackTop
    ldr x2, [x1]
    /* Save the current stack pointer */
    mov x1, sp
    str x1, [x2, -0x10]
    /* Restore the stack pointer of the master thread. This is
     * saved by either KiStartCoroutine or KiResumeCoroutine */
    ldr x1, [x2, -0x20]
    mov sp, x1
    /* Tell the master thread that we are not done yet. */
    movz x0, #STATUS_ASYNC_PENDING_WORD0
    movk x0, #STATUS_ASYNC_PENDING_WORD1, lsl #16
    /* Jump back to the address stored previously. This address is
     * provided by either KiStartCoroutine or KiResumeCoroutine */
    ldr x1, [x2, -0x18]
    br x1
.ENDP

/*
 * NTSTATUS KiResumeCoroutine(IN PVOID StackTop)   // x0
 */
.PROC KiResumeCoroutine
    COROUTINE_START_PROLOGUE
    /* Load the saved coroutine stack pointer */
    ldr x1, [x0, -0x10]
    mov sp, x1
    /* We are back to the coroutine stack now. Restore all the
     * callee-saved (non-clobbered) registers that KiYieldCoroutine
     * has saved */
    ldp x19, x20, [sp], 0x10
    ldp x21, x22, [sp], 0x10
    ldp x23, x24, [sp], 0x10
    ldp x25, x26, [sp], 0x10
    ldp x27, x28, [sp], 0x10
    ldp x29, x30, [sp], 0x10
    /* Return to whoever was calling KiYieldCoroutine */
    ret
.ENDP
