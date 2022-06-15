/*
 * COPYRIGHT: See COPYING in the top level directory
 * PROJECT: ReactOS Runtime Library(RTL)
 * FILE: lib/rtl/i386/except_asm.s
 * PURPOSE: User-mode exception support for IA-32
 * PROGRAMMERS: Alex Ionescu(alex@relsoft.net)
 * Stefan Ginsberg(stefan.ginsberg@reactos.org)
*/

/* INCLUDES******************************************************************/

#include <asm.h>
#include <ks386.h>

ExceptionContinueSearch = 1
ExceptionNestedException = 2
ExceptionCollidedUnwind = 3

/* FUNCTIONS*****************************************************************/

.code

.global _RtlpGetExceptionList@0
_RtlpGetExceptionList@0:
    /* Return the exception list */
    mov %fs:TEB_EXCEPTION_LIST, %eax
    ret


.global _RtlpSetExceptionList@4
_RtlpSetExceptionList@4:
    /* Get the new list */
    mov 4(%esp), %ecx
    mov (%ecx), %ecx

    /* Write it */
    mov %ecx, %fs:TEB_EXCEPTION_LIST

    /* Return */
    ret $4


.global _RtlCaptureContext@4
_RtlCaptureContext@4:
    /* Preserve EBX and put the context in it */
    push %ebx
    mov 8(%esp), %ebx

    /* Save the basic register context */
    mov %eax, CONTEXT_EAX(%ebx)
    mov %ecx, CONTEXT_ECX(%ebx)
    mov %edx, CONTEXT_EDX(%ebx)
    mov (%esp), %eax
    mov %eax, CONTEXT_EBX(%ebx)
    mov %esi, CONTEXT_ESI(%ebx)
    mov %edi, CONTEXT_EDI(%ebx)

    /* Capture the other regs */
    jmp CaptureRest


.global _RtlpCaptureContext@4
_RtlpCaptureContext@4:
    /* Preserve EBX and put the context in it */
    push %ebx
    mov 8(%esp), %ebx

    /* Clear the basic register context */
    movl $0, CONTEXT_EAX(%ebx)
    movl $0, CONTEXT_ECX(%ebx)
    movl $0, CONTEXT_EDX(%ebx)
    movl $0, CONTEXT_EBX(%ebx)
    movl $0, CONTEXT_ESI(%ebx)
    movl $0, CONTEXT_EDI(%ebx)

CaptureRest:
    /* Capture flags */
    pushfd
    pop CONTEXT_EFLAGS(%ebx)

    /* The return address should be in 4(%ebp) */
    mov 4(%ebp), %eax
    mov %eax, CONTEXT_EIP(%ebx)

    /* Get EBP */
    mov 0(%ebp), %eax
    mov %eax, CONTEXT_EBP(%ebx)

    /* And get ESP */
    lea 8(%ebp), %eax
    mov %eax, CONTEXT_ESP(%ebx)

    /* Return to the caller */
    pop %ebx
    ret $4


.global _RtlpExecuteHandlerForException@20
_RtlpExecuteHandlerForException@20:
    /* Copy the routine in EDX */
    mov $_RtlpExceptionProtector, %edx

    /* Jump to common routine */
    jmp _RtlpExecuteHandler@20

.global _RtlpExecuteHandlerForUnwind@20
_RtlpExecuteHandlerForUnwind@20:
    /* Copy the routine in EDX */
    mov $_RtlpUnwindProtector, %edx

.PROC _RtlpExecuteHandler@20
    FPO(0, 0, 0, 0, FRAME_FPO, 0)

    /* Save non-volatile */
    push %ebx
    push %esi
    push %edi

    /* Clear registers */
    xor %eax, %eax
    xor %ebx, %ebx
    xor %esi, %esi
    xor %edi, %edi

    /* Call the 2nd-stage executer */
    push 32(%esp)
    push 32(%esp)
    push 32(%esp)
    push 32(%esp)
    push 32(%esp)
    call _RtlpExecuteHandler2@20

    /* Restore non-volatile */
    pop %edi
    pop %esi
    pop %ebx
    ret $20

.ENDP


.global _RtlpExecuteHandler2@20
_RtlpExecuteHandler2@20:
    /* Set up stack frame */
    push %ebp
    mov %esp, %ebp

    /* Save the Frame */
    push 12(%ebp)

    /* Push handler address */
    push %edx

    /* Push the exception list */
    push %fs:TEB_EXCEPTION_LIST

    /* Link us to it */
    mov %esp, %fs:TEB_EXCEPTION_LIST

    /* Call the handler */
    push 20(%ebp)
    push 16(%ebp)
    push 12(%ebp)
    push 8(%ebp)
    mov 24(%ebp), %ecx
    call *%ecx

    /* Unlink us */
    mov %fs:TEB_EXCEPTION_LIST, %esp

    /* Restore it */
    pop %fs:TEB_EXCEPTION_LIST

    /* Undo stack frame and return */
    mov %ebp, %esp
    pop %ebp
    ret $20

_RtlpExceptionProtector:
    /* Assume we'll continue */
    mov $ExceptionContinueSearch, %eax

    /* Put the exception record in ECX and check the Flags */
    mov 4(%esp), %ecx
    testl $(EXCEPTION_UNWINDING + EXCEPTION_EXIT_UNWIND), EXCEPTION_RECORD_EXCEPTION_FLAGS(%ecx)
    jnz return

    /* Save the frame in ECX and Context in EDX */
    mov 8(%esp), %ecx
    mov 16(%esp), %edx

    /* Get the nested frame */
    mov 8(%ecx), %eax

    /* Set it as the dispatcher context */
    mov %eax, (%edx)

    /* Return nested exception */
    mov $ExceptionNestedException, %eax

return:
    ret $16

_RtlpUnwindProtector:
    /* Assume we'll continue */
    mov $ExceptionContinueSearch, %eax

    /* Put the exception record in ECX and check the Flags */
    mov 4(%esp), %ecx
    testl $(EXCEPTION_UNWINDING + EXCEPTION_EXIT_UNWIND), EXCEPTION_RECORD_EXCEPTION_FLAGS(%ecx)
    jz .return

    /* Save the frame in ECX and Context in EDX */
    mov 8(%esp), %ecx
    mov 16(%esp), %edx

    /* Get the nested frame */
    mov 8(%ecx), %eax

    /* Set it as the dispatcher context */
    mov %eax, (%edx)

    /* Return collided unwind */
    mov $ExceptionCollidedUnwind, %eax

.return:
    ret $16


.global _RtlRaiseException@4
_RtlRaiseException@4:
    /* Set up stack frame */
    push %ebp
    mov %esp, %ebp

    /*
     * Save the context while preserving everything but ESP and EBP.
     * This is vital because the caller will be restored with this context
     * in which, case the execution is continued means we must not clobber
     * the non-volatiles. We preserve the volatiles too because the context
     * could get passed to a debugger.
     */
    lea (-CONTEXT_FRAME_LENGTH)(%esp), %esp
    push %esp
    call _RtlCaptureContext@4

    /* Adjust ESP to account for the argument that was passed */
    addl $4, CONTEXT_ESP(%esp)

    /* Save the exception address */
    mov 4(%ebp), %edx
    mov 8(%ebp), %eax
    mov %edx, EXCEPTION_RECORD_EXCEPTION_ADDRESS(%eax)

    /* Write the context flag */
    movl $CONTEXT_FULL, CONTEXT_FLAGS(%esp)

    /* Check if user mode debugger is active */
    call _RtlpCheckForActiveDebugger@0
    testb %al, %al
    jnz DebuggerActive1

    /* Dispatch the exception */
    push %esp
    push 8(%ebp)
    call _RtlDispatchException@8
    testb %al, %al
    jz RaiseException

    /* Continue, go back to previous context */
    mov %esp, %ecx
    push $0
    push %ecx
    call _NtContinue@8
    jmp RaiseStatus1

DebuggerActive1:
    /* Raise an exception immediately */
    mov %esp, %ecx
    push $1
    push %ecx
    push 8(%ebp)
    call _NtRaiseException@12
    jmp RaiseStatus1

RaiseException:
    /* Raise the exception */
    mov %esp, %ecx
    push $0
    push %ecx
    push 8(%ebp)
    call _NtRaiseException@12

RaiseStatus1:
    /* If raise, we returned a status */
    push %eax
    call _RtlRaiseStatus@4


.global _RtlRaiseStatus@4
_RtlRaiseStatus@4:
    /* Set up stack frame */
    push %ebp
    mov %esp, %ebp

    /*
     * Save the context while preserving everything but ESP and EBP.
     * This is vital because the caller will be restored with this context
     * in which, case the execution is continued means we must not clobber
     * the non-volatiles. We preserve the volatiles too because the context
     * could get passed to a debugger.
     */
    lea (-CONTEXT_FRAME_LENGTH-EXCEPTION_RECORD_LENGTH)(%esp), %esp
    push %esp
    call _RtlCaptureContext@4

    /* Adjust ESP to account for the argument that was passed */
    addl $4, CONTEXT_ESP(%esp)

    /* Set up the exception record */
    lea CONTEXT_FRAME_LENGTH(%esp), %ecx
    mov 8(%ebp), %eax
    mov %eax, EXCEPTION_RECORD_EXCEPTION_CODE(%ecx)
    movl $EXCEPTION_NONCONTINUABLE, EXCEPTION_RECORD_EXCEPTION_FLAGS(%ecx)
    andl $0, EXCEPTION_RECORD_EXCEPTION_RECORD(%ecx)
    mov 4(%ebp), %eax
    mov %eax, EXCEPTION_RECORD_EXCEPTION_ADDRESS(%ecx)
    andl $0, EXCEPTION_RECORD_NUMBER_PARAMETERS(%ecx)

    /* Write the context flag */
    movl $CONTEXT_FULL, CONTEXT_FLAGS(%esp)

    /* Check if user mode debugger is active */
    call _RtlpCheckForActiveDebugger@0

    /* Restore ECX and jump if debugger is active */
    lea CONTEXT_FRAME_LENGTH(%esp), %ecx
    testb %al, %al
    jnz DebuggerActive2

    /* Dispatch the exception */
    push %esp
    push %ecx
    call _RtlDispatchException@8

    /* Raise exception if we got here */
    lea CONTEXT_FRAME_LENGTH(%esp), %ecx
    mov %esp, %edx
    push $0
    push %edx
    push %ecx
    call _NtRaiseException@12
    jmp RaiseStatus2

DebuggerActive2:
    /* Raise an exception immediately */
    mov %esp, %edx
    push $1
    push %edx
    push %ecx
    call _NtRaiseException@12

RaiseStatus2:
    /* If raise, we returned a status */
    push %eax
    call _RtlRaiseStatus@4
