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

    /* Load former stack pointer in rax */
    lea rax, [rsp + 16]

    /* Store stack pointer */
    mov [rcx + CxRsp], rax

    /* Store xmm registers */
    movaps [rcx + CxXmm0], xmm0
    movaps [rcx + CxXmm1], xmm1
    movaps [rcx + CxXmm2], xmm2
    movaps [rcx + CxXmm3], xmm3
    movaps [rcx + CxXmm4], xmm4
    movaps [rcx + CxXmm5], xmm5
    movaps [rcx + CxXmm6], xmm6
    movaps [rcx + CxXmm7], xmm7

    /* Load rflags into eax */
    mov eax, [rsp]

    movaps [rcx + CxXmm8], xmm8
    movaps [rcx + CxXmm9], xmm9
    movaps [rcx + CxXmm10], xmm10
    movaps [rcx + CxXmm11], xmm11
    movaps [rcx + CxXmm12], xmm12
    movaps [rcx + CxXmm13], xmm13
    movaps [rcx + CxXmm14], xmm14
    movaps [rcx + CxXmm15], xmm15

    /* Store legacy floating point registers */
    fxsave [rcx + CxFltSave]
    stmxcsr [rcx + CxMxCsr]

    /* Store rflags */
    mov [rcx + CxEFlags], eax

    /* Cleanup stack and return */
    add rsp, 8
    ret
.ENDP

/*
 * VOID
 * RtlpRestoreFpuContext(IN PCONTEXT ContextRecord@<rcx>);
 */
.global RtlpRestoreFpuContext
.PROC RtlpRestoreFpuContext
    .endprolog

    /* Restore legacy floating point registers (It's slow, so do it first) */
    ldmxcsr [rcx + CxMxCsr]
    fxrstor [rcx + CxFltSave]

    /* Restore xmm registers */
    movaps xmm0, [rcx + CxXmm0]
    movaps xmm1, [rcx + CxXmm1]
    movaps xmm2, [rcx + CxXmm2]
    movaps xmm3, [rcx + CxXmm3]
    movaps xmm4, [rcx + CxXmm4]
    movaps xmm5, [rcx + CxXmm5]
    movaps xmm6, [rcx + CxXmm6]
    movaps xmm7, [rcx + CxXmm7]
    movaps xmm8, [rcx + CxXmm8]
    movaps xmm9, [rcx + CxXmm9]
    movaps xmm10, [rcx + CxXmm10]
    movaps xmm11, [rcx + CxXmm11]
    movaps xmm12, [rcx + CxXmm12]
    movaps xmm13, [rcx + CxXmm13]
    movaps xmm14, [rcx + CxXmm14]
    movaps xmm15, [rcx + CxXmm15]

    ret

.ENDP
