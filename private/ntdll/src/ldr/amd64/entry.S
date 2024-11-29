#include <ksamd64.h>

.section .text

.global LdrInitializeThunk
.seh_proc LdrInitializeThunk
LdrInitializeThunk:
    /*
     * This entry point serves both as the initial entry point for a
     * thread and as the entry point for an exception. The latter case
     * is distinguished by the second parameter being non-zero.
     */
    test %rdx, %rdx
    jnz KiUserExceptionDispatcher

    /*
     * Note that since this function is entered from "kernel space",
     * ie. dispatched by the server rather than called, we push a zero
     * as the return address. Later when an exception happens RtlUnwindEx
     * will see this and will stop unwinding the stack. An added benefit
     * of this scheme is that an exit unwind is always safe, assuming
     * that all other functions conform to the amd64 unwinding ABI and
     * the call stack being unwound is the same initial stack of the
     * thread (ie. thread did not switch to a coroutine stack) and is
     * not corrupted, because under these assumptions RtlUnwindEx will
     * always hit the stack frame of the LdrInitializeThunk eventually
     * and will stop the unwind.
     */
    xor %rax, %rax
    push %rax
    push %rax

    /*
     * MSVC amd64 calling convention requires that the caller allocates
     * a 32-byte shadow area for rcx, rdx, r8 and r9.
     */
    sub $0x20, %rsp
    .seh_stackalloc 0x20
    .seh_endprologue

    /* %rcx contains the address of the TEB */
    call LdrpInitialize

    /* Should not return. */
1:  jmp  1b
.seh_endproc

.global KiUserExceptionDispatcher
.seh_proc KiUserExceptionDispatcher
KiUserExceptionDispatcher:
    /* We push a machine frame so that RtlUnwindEx can correctly unwind
     * the stack frame back to where the exception originally occurred. */
    xor %rax, %rax
    push %rax                   /* SS */
    push CxRsp(%rdx)
    push CxEFlags(%rdx)
    push %rax                   /* CS */
    push CxRip(%rdx)
    /* Push a zero as error code so stack is 16-byte aligned */
    push %rax
    /* 32-byte shadow area as required by MSVC amd64 ABI */
    sub $0x20, %rsp
    .seh_pushframe
    .seh_stackalloc 0x28        /* shadow-area plus the error code */
    .seh_endprologue
    call KiDispatchUserException
    /* This should never return. If it did, just loop forever */
1:  jmp 1b
.seh_endproc
