/*
 * C Runtime Support for Structured Exception Handling
 *
 * This code is derived from reactos/sdk/lib/pseh/i386/seh.S
 */

/* INCLUDES******************************************************************/

#include <x86asm.h>
#include <ks386.h>

DISPOSITION_DISMISS = 0
DISPOSITION_CONTINUE_SEARCH = 1
DISPOSITION_COLLIDED_UNWIND = 3

EXCEPTION_EXIT_UNWIND = 4
EXCEPTION_UNWINDING = 2

/* See seh_prolog.s */
SEH_FRAME_NewEsp = 0		/* 0x00 */
SEH_FRAME_unused = 4		/* 0x04 */
SEH_FRAME_PreviousRecord = 8	/* 0x08 */
SEH_FRAME_Handler = 12		/* 0x0c */
SEH_FRAME_SEHTable = 16		/* 0x10 */
SEH_FRAME_Disable = 20		/* 0x14 */
SEH_FRAME_OriginalEbp = 24	/* 0x18 */
SEH_FRAME_Size = 28		/* 0x1c */


/* GLOBALS****************************************************************** */

.global __global_unwind2
.global __local_unwind2
.global __abnormal_termination
.global __except_handler2
.global __except_handler3

/* FUNCTIONS*****************************************************************/

.code
_unwind_handler:
    /* Check if we were unwinding and continue search if not */
    mov 4(%esp), %ecx
    testl $(EXCEPTION_EXIT_UNWIND + EXCEPTION_UNWINDING), 4(%ecx)
    mov $DISPOSITION_CONTINUE_SEARCH, %eax
    jz unwind_handler_return

    /* We have a collision. Do a local unwind */
    mov 20(%esp), %eax
    push %ebp
    mov 16(%eax), %ebp
    mov 40(%eax), %edx
    push %edx
    mov 36(%eax), %edx
    push %edx
    call __local_unwind2
    add $8, %esp
    pop %ebp

    /* Set new try level */
    mov 8(%esp), %eax
    mov 16(%esp), %edx
    mov %eax, (%edx)

    /* Return collided unwind */
    mov $DISPOSITION_COLLIDED_UNWIND, %eax

unwind_handler_return:
    ret

__global_unwind2:
    /* Create stack and save all registers */
    push %ebp
    mov %esp, %ebp
    push %ebx
    push %esi
    push %edi
    push %ebp

    /* Call unwind */
    push $0
    push $0
    push $glu_return
    push 8(%ebp)
    call _RtlUnwind@16

glu_return:
    /* Restore registers and return */
    pop %ebp
    pop %edi
    pop %esi
    pop %ebx
    mov %ebp, %esp
    pop %ebp
    ret

__abnormal_termination:
    /* Assume false */
    xor %eax, %eax

    /* Check if the handler is the unwind handler */
    mov %fs:0, %ecx
    cmpl $_unwind_handler, 4(%ecx)
    jne ab_return

    /* Get the try level */
    mov 12(%ecx), %edx
    mov 12(%edx), %edx

    /* Compare it */
    cmp %edx, 8(%ecx)
    jne ab_return

    /* Return true */
    mov $1, %eax

/* Return */
ab_return:
    ret


__local_unwind2:
    /* Save volatiles */
    push %ebx
    push %esi
    push %edi

    /* Get the exception registration */
    mov 16(%esp), %eax

    /* Setup SEH to protect the unwind */
    push %ebp
    push %eax
    push $-2
    push $_unwind_handler
    push %fs:0
    mov %esp, %fs:0

unwind_loop:
    /* Get the exception registration and try level */
    mov 36(%esp), %eax
    mov 8(%eax), %ebx
    mov 12(%eax), %esi

    /* Validate the unwind */
    cmp $-1, %esi
    je unwind_return
    cmpl $-1, 40(%esp)
    je unwind_ok
    cmp 40(%esp), %esi
    jbe unwind_return

unwind_ok:
    /* Get the new enclosing level and save it */
    lea (%esi,%esi,2), %esi
    mov (%ebx,%esi,4), %ecx
    mov %ecx, 8(%esp)
    mov %ecx, 12(%eax)

    /* Check the filter type */
    cmpl $0, 4(%ebx, %esi, 4)
    jnz __NLG_Return2

    /* FIXME: NLG Notification */

    /* Call the handler */
    call *8(%ebx,%esi,4)

__NLG_Return2:
    /* Unwind again */
    jmp unwind_loop

unwind_return:
    /* Cleanup SEH */
    pop %fs:0x0
    add $16, %esp
    pop %edi
    pop %esi
    pop %ebx
    ret


__except_handler2:
    /* Setup stack and save volatiles */
    push %ebp
    mov %esp, %ebp
    sub $8, %esp
    push %ebx
    push %esi
    push %edi
    push %ebp

    /* Clear direction flag */
    cld

    /* Get exception registration and record */
    mov 12(%ebp), %ebx
    mov 8(%ebp), %eax

    /* Check if this is an unwind */
    testl $(EXCEPTION_EXIT_UNWIND + EXCEPTION_UNWINDING), 4(%eax)
    jnz except_unwind2

    /* Save exception pointers structure */
    mov %eax, -8(%ebp)
    mov 16(%ebp), %eax
    mov %eax, -4(%ebp)
    lea -8(%ebp), %eax
    mov %eax, 20(%ebx)

    /* Get the try level and scope table */
    mov 12(%ebx), %esi
    mov 8(%ebx), %edi

except_loop2:
    /* Validate try level */
    cmp $-1, %esi
    je except_search2

    /* Check if this is the termination handler */
    lea (%esi,%esi,2), %ecx
    cmpl $0, 4(%edi,%ecx,4)
    jz except_continue2

    /* Save registers, call filter, and then restore them */
    push %esi
    push %ebp
    mov 16(%ebx), %ebp
    call *4(%edi,%ecx,4)
    pop %ebp
    pop %esi

    /* Restore %ebx and check the result */
    mov 12(%ebp), %ebx
    or %eax, %eax
    jz except_continue2
    js except_dismiss2

    /* So this is an accept. Call the termination handlers */
    mov 8(%ebx), %edi
    push %ebx
    call __global_unwind2
    add $4, %esp

    /* Restore %ebp */
    mov 16(%ebx), %ebp

    /* Do local unwind */
    push %esi
    push %ebx
    call __local_unwind2
    add $8, %esp

    /* Set new try level */
    lea (%esi,%esi,2), %ecx
    mov (%edi,%ecx,4), %eax
    mov %eax, 12(%ebx)

    /* Call except handler */
    call *8(%edi,%ecx,4)

except_continue2:
    /* Reload try level and except again */
    mov 8(%ebx), %edi
    lea (%esi,%esi,2), %ecx
    mov (%edi,%ecx,4), %esi
    jmp except_loop2

except_dismiss2:
    /* Dismiss it */
    mov $DISPOSITION_DISMISS, %eax
    jmp except_return2

except_search2:
    /* Continue searching */
    mov $DISPOSITION_CONTINUE_SEARCH, %eax
    jmp except_return2

/* Do local unwind */
except_unwind2:
    push %ebp
    mov 16(%ebx), %ebp
    push $-1
    push %ebx
    call __local_unwind2
    add $8, %esp

    /* Retore EBP and set return disposition */
    pop %ebp
    mov $DISPOSITION_CONTINUE_SEARCH, %eax

except_return2:
    /* Restore registers and stack */
    pop %ebp
    pop %edi
    pop %esi
    pop %ebx
    mov %ebp, %esp
    pop %ebp
    ret

/*
 * ROUTINE DESCRIPTION:
 *     C-language specific exception handler. This is installed
 *     by MSVC (or any compatible compiler) as the generic SEH
 *     exception handler for all functions with a __try/__except
 *     or __try/__finally construct. It is invoked by the system
 *     in RtlpExecuteHandlerForException or RtlpExecuteHandlerForUnwind.
 *
 * PROTOTYPE:
 *
 *     EXCEPTION_DISPOSITION NTAPI
 *     __except_handler3(IN OUT PEXCEPTION_RECORD ExceptionRecord,
 *                       IN PVOID EstablisherFrame,
 *                       IN OUT PCONTEXT ContextRecord,
 *                       IN PVOID DispatcherContext);
 *
 * ARGUMENTS:
 *    See RtlDispatchException and RtlUnwind for the arguments
 *    passed by the system during exception dispatching and unwinding.
 *
 */
__except_handler3:
PARAM_ExceptionRecord = 8
PARAM_RegistrationFrame = 12
PARAM_Context = 16
    /* Setup stack and save volatiles */
    push %ebp
    mov %esp, %ebp
    sub $8, %esp
    push %ebx
    push %esi
    push %edi
    push %ebp

    /* Clear direction flag */
    cld

    /* Get exception registration and record */
    mov PARAM_RegistrationFrame(%ebp), %ebx
    mov PARAM_ExceptionRecord(%ebp), %eax

    /* Check if this is an unwind */
    testl $(EXCEPTION_EXIT_UNWIND + EXCEPTION_UNWINDING), EXCEPTION_RECORD_EXCEPTION_FLAGS(%eax)
    jnz except_unwind3

    /* Save exception pointers structure */
    mov %eax, (EXCEPTION_POINTERS_EXCEPTION_RECORD - 8)(%ebp)
    mov PARAM_Context(%ebp), %eax
    mov %eax, (EXCEPTION_POINTERS_CONTEXT_RECORD - 8)(%ebp)
    lea -8(%ebp), %eax
    mov %eax, (SEH_FRAME_unused - SEH_FRAME_PreviousRecord)(%ebx)

    /* Get the try level and scope table */
    mov (SEH_FRAME_Disable - SEH_FRAME_PreviousRecord)(%ebx), %esi
    mov (SEH_FRAME_SEHTable - SEH_FRAME_PreviousRecord)(%ebx), %edi

    /* FIXME: Validate the SEH exception */

except_loop3:
    /* Validate try level */
    cmp $-1, %esi
    je except_search3

    /* Check if this is the termination handler */
    lea (%esi,%esi,2), %ecx
    mov 4(%edi,%ecx,4), %eax
    test %eax, %eax
    jz except_continue3

    /* Save registers and clear them all */
    push %esi
    push %ebp
    lea (SEH_FRAME_OriginalEbp - SEH_FRAME_PreviousRecord)(%ebx), %ebp
    xor %ebx, %ebx
    xor %ecx, %ecx
    xor %edx, %edx
    xor %esi, %esi
    xor %edi, %edi

    /* Call the filter and restore our registers */
    call *%eax
    pop %ebp
    pop %esi

    /* Restore %ebx and check the result */
    mov PARAM_RegistrationFrame(%ebp), %ebx
    test %eax, %eax
    /* If the return value of the exception filter is zero (ie.
     * EXCEPTION_CONTINUE_SEARCH, note that this is different from
     * ExceptionContinueSearch, which is defined as one), continue
     * the search at the next (ie. outer) try level. */
    jz except_continue3
    /* If the return value of the exception filter is negative
     * (typically -1, ie. EXCEPTION_CONTINUE_EXECUTION), exit the
     * loop and return from the C-language exception handler with
     * the disposition ExceptionContinueExecution. */
    js except_dismiss3

    /* If neither cases above is true, the return value of the
     * exception filter (typically EXCEPTION_EXECUTE_HANDLER)
     * indicates that we need to execute the __except block.
     * Before doing that, we need to perform a global unwind
     * followed by a local unwind such that all termination
     * handlers (__finally blocks) up to this SEH scope will be
     * executed. This will also ensure that the stack pointer
     * points to the frame that corresponds to the __except
     * block to be executed. */
    mov (SEH_FRAME_SEHTable - SEH_FRAME_PreviousRecord)(%ebx), %edi
    push %ebx
    call __global_unwind2
    add $4, %esp

    /* Restore %ebp */
    lea (SEH_FRAME_OriginalEbp - SEH_FRAME_PreviousRecord)(%ebx), %ebp

    /* Do local unwind */
    push %esi
    push %ebx
    call __local_unwind2
    add $8, %esp

    /* FIXME: Do NLG Notification */

    /* Set new try level */
    lea (%esi,%esi,2), %ecx
    mov (%edi,%ecx,4), %eax
    mov %eax, (SEH_FRAME_Disable - SEH_FRAME_PreviousRecord)(%ebx)

    /* Clear registers and call except handler */
    mov 8(%edi,%ecx,4), %eax
    xor %ebx, %ebx
    xor %ecx, %ecx
    xor %edx, %edx
    xor %esi, %esi
    xor %edi, %edi
    call *%eax

except_continue3:
    /* Reload try level and except again */
    mov (SEH_FRAME_SEHTable - SEH_FRAME_PreviousRecord)(%ebx), %edi
    lea (%esi, %esi, 2), %ecx
    mov (%edi, %ecx, 4), %esi
    jmp except_loop3

except_dismiss3:
    /* Dismiss it */
    mov $DISPOSITION_DISMISS, %eax
    jmp except_return3

/* Do local unwind */
except_unwind3:
    push %ebp
    lea (SEH_FRAME_OriginalEbp - SEH_FRAME_PreviousRecord)(%ebx), %ebp
    push $-1
    push %ebx
    call __local_unwind2
    add $8, %esp

    /* Restore EBP */
    pop %ebp

except_search3:
    /* Continue searching */
    mov $DISPOSITION_CONTINUE_SEARCH, %eax

except_return3:
    /* Restore registers and stack */
    pop %ebp
    pop %edi
    pop %esi
    pop %ebx
    mov %ebp, %esp
    pop %ebp
    ret
