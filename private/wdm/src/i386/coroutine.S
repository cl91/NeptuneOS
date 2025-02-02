#include <wdmasm.h>

#define COROUTINE_START_PROLOGUE			;\
    /* KiCurrentCoroutineStackTop = StackTop (%ecx); */ ;\
    mov %ecx, _KiCurrentCoroutineStackTop		;\
    /* Save all callee-saved (non-volatile) registers */;\
    push %ebx						;\
    push %esi						;\
    push %edi						;\
    push %ebp						;\
    /* Save the master thread stack pointer */		;\
    mov %esp, -0x10(%ecx)				;\
    /* Save the address to KiExitCoroutine so		;\
     * KiYieldCoroutine knowns where to jump to */	;\
    movl $KiExitCoroutine, -0xc(%ecx)

/*
 * NTSTATUS KiStartCoroutine(IN PVOID StackTop,                        // 0x4(%esp)
 *                           IN KI_COROUTINE_ENTRYPOINT EntryPoint,    // 0x8(%esp)
 *                           IN PVOID Context)                         // 0xc(%esp)
 */
.global _KiStartCoroutine
_KiStartCoroutine:
    /* Load the StackTop to %ecx */
    mov 0x4(%esp), %ecx
    /* Load the EntryPoint to %eax */
    mov 0x8(%esp), %eax
    /* Load the Context pointer to %edx */
    mov 0xc(%esp), %edx
    COROUTINE_START_PROLOGUE
    /* Switch to the stack pointer given by StackTop (%ecx). */
    mov %ecx, %esp
    /* Skip the KI_COROUTINE_STACK struct */
    sub $0x10, %esp
    /* EntryPoint is FASTCALL so set up its sole argument */
    mov %edx, %ecx
    /*
     * GCC expects that a C function is always entered via a call
     * instruction and that the stack is 16-byte aligned before
     * such an instruction (leaving it 16-byte aligned + 1 word
     * from the implicit push when the function is entered).
     */
    call *%eax
    /* Restore the old stack pointer. Note after the coroutine
     * is suspended and later resumed, this stack pointer refers
     * to the stack frame of KiResumeCoroutine rather than
     * KiStartCoroutine. */
    pop %esp
KiExitCoroutine:
    /* Restore all callee-saved (non-clobbered) registers.
     * Note this is where KiCoroutineYield jumps to */
    pop %ebp
    pop %edi
    pop %esi
    pop %ebx
    /* KiCurrentCoroutineStackTop = NULL; */
    movl $0, _KiCurrentCoroutineStackTop
    /* Pop %eip. Note this code path is shared by KiStartCoroutine
     * and KiResumeCoroutine. This implies that KiResumeCoroutine
     * cannot have more than two arguments, since it is FASTCALL
     * and FASTCALL is callee-cleanup for stack arguments. */
    ret

/*
 * KiYieldCoroutine()
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
    /* Save the current stack pointer */
    movl %esp, -0x8(%ecx)
    /* Restore the stack pointer of the master thread. This is
     * saved by either KiStartCoroutine or KiResumeCoroutine */
    movl -0x10(%ecx), %esp
    /* Tell the master thread that we are not done yet. */
    movl $STATUS_ASYNC_PENDING, %eax
    /* Jump back to the address stored previously. This address is
     * provided by either KiStartCoroutine or KiResumeCoroutine */
    jmp *-0xc(%ecx)

/*
 * FASTCALL NTSTATUS KiResumeCoroutine(IN PVOID StackTop)   // %ecx
 */
.global @KiResumeCoroutine@4
@KiResumeCoroutine@4:
    COROUTINE_START_PROLOGUE
    /* Load the saved coroutine stack pointer */
    mov -0x8(%ecx), %esp
    /* We are back to the coroutine stack now. Restore all the
     * callee-saved (non-clobbered) registers that KiYieldCoroutine
     * has saved */
    pop %ebp
    pop %edi
    pop %esi
    pop %ebx
    /* Return to whoever was calling KiYieldCoroutine */
    ret
