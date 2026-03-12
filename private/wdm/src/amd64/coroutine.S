#include <wdmasm.h>

#define SAVE_REGS					\
    /* Save all callee-saved (non-volatile) registers */;\
    push %rbx						;\
    push %rsi						;\
    push %rdi						;\
    push %rbp						;\
    push %r12						;\
    push %r13						;\
    push %r14						;\
    push %r15						;\
    /* Save callee-saved XMM registers */		;\
    sub $0xa0, %rsp					;\
    movdqu %xmm6,  0x00(%rsp)				;\
    movdqu %xmm7,  0x10(%rsp)				;\
    movdqu %xmm8,  0x20(%rsp)				;\
    movdqu %xmm9,  0x30(%rsp)				;\
    movdqu %xmm10, 0x40(%rsp)				;\
    movdqu %xmm11, 0x50(%rsp)				;\
    movdqu %xmm12, 0x60(%rsp)				;\
    movdqu %xmm13, 0x70(%rsp)				;\
    movdqu %xmm14, 0x80(%rsp)				;\
    movdqu %xmm15, 0x90(%rsp)

#define RESTORE_REGS					\
    movdqu 0x00(%rsp), %xmm6				;\
    movdqu 0x10(%rsp), %xmm7				;\
    movdqu 0x20(%rsp), %xmm8				;\
    movdqu 0x30(%rsp), %xmm9				;\
    movdqu 0x40(%rsp), %xmm10				;\
    movdqu 0x50(%rsp), %xmm11				;\
    movdqu 0x60(%rsp), %xmm12				;\
    movdqu 0x70(%rsp), %xmm13				;\
    movdqu 0x80(%rsp), %xmm14				;\
    movdqu 0x90(%rsp), %xmm15				;\
    add $0xA0, %rsp					;\
    pop %r15						;\
    pop %r14						;\
    pop %r13						;\
    pop %r12						;\
    pop %rbp						;\
    pop %rdi						;\
    pop %rsi						;\
    pop %rbx

#define COROUTINE_START_PROLOGUE			;\
    /* KiCurrentCoroutineStackTop = StackTop (%rcx); */	;\
    movq %rcx, KiCurrentCoroutineStackTop(%rip)		;\
    SAVE_REGS						;\
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
    RESTORE_REGS
    /* KiCurrentCoroutineStackTop = NULL; */
    movq $0, KiCurrentCoroutineStackTop(%rip)
    /* Pop %rip */
    ret

/*
 * KiYieldCoroutine()
 */
.global KiYieldCoroutine
KiYieldCoroutine:
    SAVE_REGS
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
    RESTORE_REGS
    /* Return to whoever was calling KiYieldCoroutine */
    ret
