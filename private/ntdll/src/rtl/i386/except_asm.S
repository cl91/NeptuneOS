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


/*
 * ROUTINE DESCRIPTION:
 *     Captures the current execution environment (integer and control
 *     registers only, no floating point), with the exception of the
 *     instruction pointer, stack pointer, and the base pointer. Instead,
 *     the instruction pointer is set to the return address of the caller
 *     of this function (ie. the caller of whoever called us). The base
 *     pointer is set to the base pointer of the previous call frame (ie.
 *     the base pointer of the caller of the caller of this function),
 *     and the stack pointer is set to the stack pointer at the point of
 *     the call instruction when the caller's caller called the caller.
 *
 * ADDITIONAL INFORMATION:
 *     Note that this is not used by RtlUnwind. We only expose this
 *     because it is a public function.
 *
 *     Also note that in order for this function to work correctly,
 *     the caller must NOT have its frame pointer omitted. Since most
 *     modern compilers WILL omit the frame pointers, you are strongly
 *     advised to NOT call this function unless you are sure the frame
 *     pointer is not omitted. RtlRaiseStatus and RtlRaiseException do
 *     call this function, but they are asm functions and set up their
 *     frame pointers manually, so there is no danger.
 *
 * SCHEMATIC DIAGRAM OF THE CAPTURED STACK FRAME:
 *
 *     The following is the stack organization when this routine
 *     is entered:
 *
 *         LOWER ADDRESS               HIGHER ADDRESS
 *         ------------------------------------------
 *         |RetAddr|Context|....|OldEBP|RetAddr1|....
 *         ^                    ^               ^
 *         ESP                  EBP             Old ESP
 *
 *     On exit, Context->Eip is set to RetAddr1, Context->Ebp
 *     is set to OldEBP, and Context->Esp is set to OldESP.
 */
.global _RtlCaptureContext@4
_RtlCaptureContext@4:
    /* Save the current EBX and put the context pointer in it */
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


/* See RtlpExecuteHandler for stack and register usage */
.global _RtlpExecuteHandlerForException@20
_RtlpExecuteHandlerForException@20:
    /* Copy the routine in EDX */
    mov $_RtlpExceptionProtector@16, %edx

    /* Jump to common routine */
    jmp _RtlpExecuteHandler@20

/* See RtlpExecuteHandler for stack and register usage */
.global _RtlpExecuteHandlerForUnwind@20
_RtlpExecuteHandlerForUnwind@20:
    /* Copy the routine in EDX */
    mov $_RtlpUnwindProtector@16, %edx

/*
 * ROUTINE DESCRIPTION:
 *     Setup the exception protector and execute the exception
 *     or unwind handler specified in %edx. This routine simply
 *     cleans up the unused registers (so they don't get leaked
 *     into the second stage executor) and calls the second stage
 *     executor to do the heavy lifting.
 *
 * PROTOTYPE:
 *     EXCEPTION_DISPOSITION NTAPI
 *     RtlpExecuteHandler(IN PEXCEPTION_RECORD ExceptionRecord,
 *                        IN PVOID EstablisherFrame,
 *                        IN OUT PCONTEXT ContextRecord,
 *                        IN OUT PVOID DispatcherContext,
 *                        IN PEXCEPTION_ROUTINE ExceptionRoutine);
 *
 * ADDITIONAL INFORMATION:
 *     On entry, the stack organization is as follows:
 *
 *     LOWER ADDRESS                          HIGHER ADDRESS
 *     -----------------------------------------------------
 *     |RetAddr|ExceptRec|EstFrame|CtxRec|DispCtx|ExRoutine|
 *     -----------------------------------------------------
 *     ^       ^         ^        ^      ^       ^
 *     ESP     ESP+4     ESP+8    ESP+12 ESP+16  ESP+20
 *
 *     On entry, EDX has the address to the exception/unwind
 *     protector. EBX, ESI, EDI are saved to the stack and then
 *     cleared before calling the second stage executor. EAX
 *     and ECX are cleared. EBP is not modified throughout this
 *     routine (the second stage executor will modify EBP).
 */
.PROC _RtlpExecuteHandler@20
    FPO(0, 0, 0, 0, FRAME_FPO, 0)

    /* Save non-volatile */
    push %ebx
    push %esi
    push %edi

    /* Clear registers */
    xor %eax, %eax
    xor %ecx, %ecx
    xor %ebx, %ebx
    xor %esi, %esi
    xor %edi, %edi

    /* Call the 2nd-stage executor */
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

/*
 * ROUTINE DESCRIPTION:
 *     Second stage executor for the RtlpExecuteHandler routine.
 *
 * PROTOTYPE:
 *     Same as RtlpExecuteHandler.
 *
 * ADDITIONAL INFORMATION:
 *     On entry, the stack organization is as follows:
 *
 *     LOWER ADDRESS                           HIGHER ADDRESS
 *     ------------------------------------------------------
 *     |RetAddr|ExRec...ExRoutine|OldEDI|OldESI|OldEBX|Ret...
 *     ------------------------------------------------------
 *     ^       ^                 ^     ^      ^      ^
 *     ESP     ESP+4          ESP+20  (PUSHED BY 1ST STAGE)
 *
 *     On entry, EDX has the address to the exception/unwind
 *     protector. EAX, EBX, ECX, ESI, and EDI are set to zero.
 */
.global _RtlpExecuteHandler2@20
_RtlpExecuteHandler2@20:
    /* Set up stack frame */
    push %ebp
    mov %esp, %ebp

    /* Setup the extended exception registration record
     * for use by the exception/unwind protector. This
     * is an extension to the EXCEPTION_REGISTRATION_RECORD
     * with an additional member, the EstablisherFrame.
     *
     * struct _EXTENDED_EXCEPTION_REGISTRATION_RECORD {
     *     EXCEPTION_REGISTRATION_RECORD   SubRecord;
     *     PVOID                           EstablisherFrame;
     * };
     *
     * NOTE: Do NOT confuse this with the extended exception
     * registration record used by the C-language specific
     * handler, __except_handler3. This is for the exception/
     * unwind protector only.
     *
     * First, we push the establisher frame. */
    push 12(%ebp)

    /* Push the address of the exception/unwind protector */
    push %edx

    /* Push the current head of the exception list */
    push %fs:TEB_EXCEPTION_LIST

    /* Link us to the exception list as its new head */
    mov %esp, %fs:TEB_EXCEPTION_LIST

    /* Call the specified exception or unwind handler. This handler
     * is typically the language-specific handler (for MSVC, it is
     * __except_handler3 or an equivalent function). The handler has
     * the following prototype:
     *
     *   EXCEPTION_DISPOSITION NTAPI
     *   ExceptionHandler(IN OUT PEXCEPTION_RECORD ExceptionRecord,
     *                    IN PVOID EstablisherFrame,
     *                    IN OUT PCONTEXT ContextRecord,
     *                    IN PVOID DispatcherContext);
     *
     * Note that at this point the stack organization is as follows:
     *
     *   LOWER ADDRESS                                 HIGHER ADDRESS
     *   ------------------------------------------------------------
     *   |PrevExList|Ex/UwProtector|EstFrame|OldEBP|RetAddr|ExRec|...
     *   ------------------------------------------------------------
     *   ^          ^              ^        ^              ^
     *   ESP        ESP+4          ESP+8    EBP, ESP+12    EBP+8
     */
    push 20(%ebp)
    push 16(%ebp)
    push 12(%ebp)
    push 8(%ebp)
    mov 24(%ebp), %ecx
    call *%ecx

    /* Restore the stack pointer to what was before the handler call */
    mov %fs:TEB_EXCEPTION_LIST, %esp

    /* Restore the previous head of the exception list.
     * This will unlink us from the exception list. */
    pop %fs:TEB_EXCEPTION_LIST

    /* Undo stack frame and return */
    mov %ebp, %esp
    pop %ebp
    ret $20

/*
 * ROUTINE DESCRIPTION:
 *     Protector for nested exceptions. This will be executed
 *     when another exception occurs in an exception handler
 *     while the system is dispatching an exception. It retrieves
 *     the establisher frame address and the handler address
 *     of the previous exception and places them in the supplied
 *     dispatcher context record. It then returns the disposition
 *     ExceptionNestedException to inform the system of a nested
 *     exception.
 *
 * PROTOTYPE:
 *     EXCEPTION_DISPOSITION NTAPI
 *     RtlpExceptionProtector(IN PEXCEPTION_RECORD ExceptionRecord,
 *                            IN PVOID EstablisherFrame,
 *                            IN OUT PCONTEXT ContextRecord,
 *                            IN OUT PVOID DispatcherContext);
 *
 * ADDITIONAL INFORMATION:
 *     On entry, the stack organization is as follows:
 *
 *     LOWER ADDRESS            HIGHER ADDRESS
 *     ---------------------------------------
 *     |RetAddr|ExRec|EstFrame|CtxRec|DispCtx|
 *     ---------------------------------------
 *     ^       ^     ^        ^      ^
 *     ESP     ESP+4 ESP+8    ESP+12 ESP+16
 *
 */
_RtlpExceptionProtector@16:
    /* Assume we'll continue */
    mov $ExceptionContinueSearch, %eax

    /* Put the exception record in ECX and check the Flags */
    mov 4(%esp), %ecx
    testl $(EXCEPTION_UNWINDING + EXCEPTION_EXIT_UNWIND), EXCEPTION_RECORD_EXCEPTION_FLAGS(%ecx)
    jnz 1f

    /* Copy the establisher frame in ECX and Context in EDX */
    mov 8(%esp), %ecx
    mov 16(%esp), %edx

    /* Get the nested frame */
    mov 8(%ecx), %eax

    /* Set it as the dispatcher context */
    mov %eax, (%edx)

    /* Return nested exception */
    mov $ExceptionNestedException, %eax
1:
    ret $16

/*
 * ROUTINE DESCRIPTION:
 *     Protector for collided unwind. This serves the same role
 *     as the nested exception protector when it is called during
 *     RtlUnwind. The function prototype, as well as the stack
 *     organization is exactly the same as RtlpExceptionProtector.
 */
_RtlpUnwindProtector@16:
    /* Assume we'll continue */
    mov $ExceptionContinueSearch, %eax

    /* Put the exception record in ECX and check the Flags */
    mov 4(%esp), %ecx
    testl $(EXCEPTION_UNWINDING + EXCEPTION_EXIT_UNWIND), EXCEPTION_RECORD_EXCEPTION_FLAGS(%ecx)
    jz 1f

    /* Copy the establisher frame in ECX and Context in EDX */
    mov 8(%esp), %ecx
    mov 16(%esp), %edx

    /* Get the nested frame */
    mov 8(%ecx), %eax

    /* Set it as the dispatcher context */
    mov %eax, (%edx)

    /* Return collided unwind */
    mov $ExceptionCollidedUnwind, %eax
1:
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
