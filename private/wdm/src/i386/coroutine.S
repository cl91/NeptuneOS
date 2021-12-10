#include <wdmasm.h>

/*
 * FASTCALL NTSTATUS IopStartCoroutine(IN PVOID StackTop,   // %ecx
 *                                     IN PIRP_QUEUE_ENTRY CurrentIrp)  // %edx
 */
.global @IopStartCoroutine@8
@IopStartCoroutine@8:
    /* KiCurrentCoroutineStackTop = StackTop (%ecx); */
    mov %ecx, _KiCurrentCoroutineStackTop
    /* Save all callee-saved (non-clobbered) registers */
    push %ebx
    push %esi
    push %edi
    push %ebp
    /* Switch to the stack pointer given by StackTop (%ecx). */
    mov %esp, %eax
    mov %ecx, %esp
    /* Copy the CurrentIrp queue entry pointer (%edx) to %ecx */
    mov %edx, %ecx
    /* Skip the NextStackTop pointer */
    sub $0x4, %esp
    /* Save the CurrentIrp queue entry pointer */
    push %ecx
    /* Save the return address for KiCoroutineYield to jump to */
    push $1f
    /* Save the old stack pointer */
    push %eax
    /*
     * GCC expects that a C function is always entered via a call
     * instruction and that the stack is 16-byte aligned before
     * such an instruction (leaving it 16-byte aligned + 1 word
     * from the implicit push when the function is entered).
     */
    call @IopCallDispatchRoutine@4
    /* Restore the old stack pointer. */
    pop %esp
    /* Restore %ecx from KiCurrentCoroutineStackTop */
    movl _KiCurrentCoroutineStackTop, %ecx
1:  /* Restore all callee-saved (non-clobbered) registers.
     * Note this is where KiCoroutineYield jumps to */
    pop %ebp
    pop %edi
    pop %esi
    pop %ebx
    /* ((PKI_COROUTINE_STACK)StackTop)[-1].CurrentIrp = NULL; */
    movl $0, -0x8(%ecx)
    /* KiCurrentCoroutineStackTop = NULL; */
    movl $0, _KiCurrentCoroutineStackTop
    /* Pop %eip */
    ret

/*
 * VOID KiYieldCoroutine()
 */
.global _KiYieldCoroutine
_KiYieldCoroutine:
    /* Save all callee-saved (non-clobbered) registers */
    push %ebx
    push %esi
    push %edi
    push %ebp
    /* Load the current coroutine stack top to %ecx */
    movl _KiCurrentCoroutineStackTop, %ecx
    /* Load the CurrentIrp queue entry to %eax */
    movl -0x8(%ecx), %eax
    /* Save the current stack pointer and instruction pointer
     * to the current IRP queue entry being processed */
    movl %esp, IrpSavedStackPointer(%eax)
    movl $1f, IrpSavedInstructionPointer(%eax)
    /* Restore the stack pointer and instruction pointer
     * saved by IopStartCoroutine. */
    movl -0x10(%ecx), %esp
    /* Note that after this instruction the control flow is
     * transfered to the label 1 of IopStartCoroutine */
    jmp *-0xc(%ecx)
1:  /* Restore all callee-saved (non-clobbered) registers */
    pop %ebp
    pop %edi
    pop %esi
    pop %ebx
