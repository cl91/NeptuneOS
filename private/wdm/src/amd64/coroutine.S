#include <wdmasm.h>

.global IopStartCoroutine
IopStartCoroutine:
    /* KiCurrentCoroutineStackTop = StackTop (%rcx); */
    mov %rcx, KiCurrentCoroutineStackTop
    /* Save all callee-saved (non-clobbered) registers */
    push %rbx
    push %rsi
    push %rdi
    push %rbp
    push %r12
    push %r13
    push %r14
    push %r15
    /* Switch to the stack pointer given by StackTop (%rcx). */
    mov %rsp, %rax
    mov %rcx, %rsp
    /* Copy the CurrentIrp queue entry pointer (%rdx) to %rcx */
    mov %rdx, %rcx
    /* Skip the NextStackTop pointer */
    sub $0x8, %rsp
    /* Save the CurrentIrp queue entry pointer */
    push %rcx
    /* Save the return address for KiCoroutineYield to jump to */
    push $1f
    /* Save the old stack pointer */
    push %rax
    /*
     * In the Microsoft x64 calling convention, it is the caller's
     * responsibility to allocate 32 bytes of shadow space on the
     * stack right before calling the function (regardless of the
     * actual number of parameters used), and to pop the stack
     * after the call. The shadow space is used to spill RCX, RDX,
     * R8, and R9, but must be made available to all functions,
     * even those with fewer than four parameters.
     */
    sub $0x20, %rsp
    call IopCallDispatchRoutine
    /* Skip the shadow space. */
    add $0x20, %rsp
    /* Restore the old stack pointer. */
    pop %rsp
    /* Restore %rcx from KiCurrentCoroutineStackTop */
    movq KiCurrentCoroutineStackTop, %rcx
1:  /* Restore all callee-saved (non-clobbered) registers.
     * Note this is where KiCoroutineYield jumps to */
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbp
    pop %rdi
    pop %rsi
    pop %rbx
    /* ((PKI_COROUTINE_STACK)StackTop)[-1].CurrentIrp = NULL; */
    movq $0, -0x10(%rcx)
    /* KiCurrentCoroutineStackTop = NULL; */
    movq $0, KiCurrentCoroutineStackTop
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
    movq KiCurrentCoroutineStackTop, %rcx
    /* Load the CurrentIrp queue entry to %rax */
    movq -0x10(%rcx), %rax
    /* Save the current stack pointer and instruction pointer
     * to the current IRP queue entry being processed */
    movq %rsp, IrpSavedStackPointer(%rax)
    movq $1f, IrpSavedInstructionPointer(%rax)
    /* Restore the stack pointer and instruction pointer
     * saved by IopStartCoroutine. */
    movq -0x20(%rcx), %rsp
    /* Note that after this instruction the control flow is
     * transfered to the label 1 of IopStartCoroutine */
    jmp *-0x18(%rcx)
1:  /* Restore all callee-saved (non-clobbered) registers */
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbp
    pop %rdi
    pop %rsi
    pop %rbx
