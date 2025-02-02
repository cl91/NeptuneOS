#include <wdmasm.h>

#define COROUTINE_START_PROLOGUE			;\
    /* KiCurrentCoroutineStackTop = StackTop (%rcx); */	;\
    movq %rcx, KiCurrentCoroutineStackTop(%rip)		;\
    /* Save all callee-saved (non-volatile) registers */;\
    push %rbx						;\
    push %rsi						;\
    push %rdi						;\
    push %rbp						;\
    push %r12						;\
    push %r13						;\
    push %r14						;\
    push %r15						;\
    /* Save the master thread stack pointer */		;\
    movq %rsp, -0x20(%rcx)				;\
    /* Save the address to KiExitCoroutine so		;\
     * KiYieldCoroutine knowns where to jump to */	;\
    leaq KiExitCoroutine(%rip), %rax			;\
    movq %rax, -0x18(%rcx)

/*
 * NTSTATUS KiStartCoroutine(IN PVOID StackTop,                        // %rcx
 *                           IN KI_COROUTINE_ENTRYPOINT EntryPoint,    // %rdx
 *                           IN PVOID Context)                         // %r8
 */
.global KiStartCoroutine
KiStartCoroutine:
    COROUTINE_START_PROLOGUE
    /* Switch to the stack pointer given by StackTop (%rcx). */
    mov %rcx, %rsp
    /* Skip the KI_COROUTINE_STACK struct and the shadow space.
     *
     * Note: In the Microsoft x64 calling convention, it is the
     * caller's responsibility to allocate 32 bytes of shadow space
     * on the stack right before calling the function (regardless
     * of the actual number of parameters used), and to pop the stack
     * after the call. The shadow space is used to spill RCX, RDX,
     * R8, and R9, but must be made available to all functions, even
     * those with fewer than four parameters.
     */
    sub $0x40, %rsp
    /* Call the coroutine entry point */
    mov %r8, %rcx
    call *%rdx
    /* Skip the shadow space */
    add $0x20, %rsp
    /* Restore the old stack pointer. Note after the coroutine
     * is suspended and later resumed, this stack pointer refers
     * to the stack frame of KiResumeCoroutine rather than
     * KiStartCoroutine. */
    pop %rsp
KiExitCoroutine:
    /* Restore all callee-saved (non-clobbered) registers.
     * Note this is where KiYieldCoroutine jumps to */
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbp
    pop %rdi
    pop %rsi
    pop %rbx
    /* KiCurrentCoroutineStackTop = NULL; */
    movq $0, KiCurrentCoroutineStackTop(%rip)
    /* Pop %rip */
    ret

/*
 * KiYieldCoroutine()
 */
.global KiYieldCoroutine
KiYieldCoroutine:
    /* Save all callee-saved (non-clobbered) registers */
    push %rbx
    push %rsi
    push %rdi
    push %rbp
    push %r12
    push %r13
    push %r14
    push %r15
    /* Load the current coroutine stack top to %rcx */
    movq KiCurrentCoroutineStackTop(%rip), %rcx
    /* Save the current stack pointer */
    movq %rsp, -0x10(%rcx)
    /* Restore the stack pointer of the master thread. This is
     * saved by either KiStartCoroutine or KiResumeCoroutine */
    movq -0x20(%rcx), %rsp
    /* Tell the master thread that we are not done yet. */
    movq $STATUS_ASYNC_PENDING, %rax
    /* Jump back to the address stored previously. This address is
     * provided by either KiStartCoroutine or KiResumeCoroutine */
    jmp *-0x18(%rcx)

/*
 * NTSTATUS KiResumeCoroutine(IN PVOID StackTop)   // %rcx
 */
.global KiResumeCoroutine
KiResumeCoroutine:
    COROUTINE_START_PROLOGUE
    /* Load the saved coroutine stack pointer */
    movq -0x10(%rcx), %rsp
    /* We are back to the coroutine stack now. Restore all the
     * callee-saved (non-clobbered) registers that KiYieldCoroutine
     * has saved */
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbp
    pop %rdi
    pop %rsi
    pop %rbx
    /* Return to whoever was calling KiYieldCoroutine */
    ret
