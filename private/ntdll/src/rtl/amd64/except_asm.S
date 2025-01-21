/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Runtime Library (RTL)
 * FILE:            lib/rtl/amd64/except_asm.S
 * PURPOSE:         Exception support for AMD64
 * PROGRAMMERS:     Timo Kreuzer (timo.kreuzer@reactos.org)
 */

/* INCLUDES ******************************************************************/

#include <x86asm.h>
#include <ksamd64.h>
.intel_syntax noprefix

/* FUNCTIONS *****************************************************************/

.code64

/*
 * VOID RtlCaptureContext(OUT PCONTEXT ContextRecord@<rcx>);
 */
.global RtlCaptureContext
.PROC RtlCaptureContext

    /* Push rflags */
    pushfq
    .allocstack 8
    .endprolog

    /* Save rax first, we use it later to copy some data */
    mov [rcx + CxRax], rax

    /* Set ContextFlags */
    mov dword ptr [rcx + CxContextFlags], CONTEXT_FULL

    /* Store the basic register context */
    mov [rcx + CxRcx], rcx
    mov [rcx + CxRdx], rdx
    mov [rcx + CxRbx], rbx
    mov [rcx + CxRsi], rsi

    /* Load return address in rax */
    mov rax, [rsp + 8]

    mov [rcx + CxRdi], rdi
    mov [rcx + CxRbp], rbp
    mov [rcx + CxR8], r8
    mov [rcx + CxR9], r9
    mov [rcx + CxR10], r10

    /* Store the return address */
    mov [rcx + CxRip], rax

    mov [rcx + CxR11], r11
    mov [rcx + CxR12], r12
    mov [rcx + CxR13], r13
    mov [rcx + CxR14], r14
    mov [rcx + CxR15], r15

    /* Save the FPU context */
    call RtlpSaveFpuContext

    /* Load former stack pointer in rax */
    lea rax, [rsp + 16]

    /* Store stack pointer */
    mov [rcx + CxRsp], rax

    /* Load rflags into eax */
    mov eax, [rsp]

    /* Store rflags */
    mov [rcx + CxEFlags], eax

    /* Save fs and gs base */
    rdfsbase rax
    mov [rcx + CxFsBase], rax
    rdgsbase rax
    mov [rcx + CxGsBase], rax

    /* Cleanup stack and return */
    add rsp, 8
    ret
.ENDP

/*
 * VOID
 * RtlpSaveFpuContext(IN PCONTEXT ContextRecord@<rcx>);
 */
.global RtlpSaveFpuContext
.PROC RtlpSaveFpuContext
    .endprolog
    fxsave [rcx + CxFltSave]
    ret
.ENDP

/*
 * VOID
 * RtlpRestoreFpuContext(IN PCONTEXT ContextRecord@<rcx>);
 */
.global RtlpRestoreFpuContext
.PROC RtlpRestoreFpuContext
    .endprolog
    fxrstor [rcx + CxFltSave]
    ret
.ENDP
