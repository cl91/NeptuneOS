/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS system libraries
 * FILE:        dll/win32/kernel32/client/amd64/fiber.S
 * PURPOSE:     Fiber context switch code for the amd64 architecture
 * PROGRAMMER:
 */

#include <x86asm.h>
#include <ksamd64.h>
.intel_syntax noprefix

PUBLIC RtlpCaptureFiberContext
FUNC RtlpCaptureFiberContext
    .endprolog
    mov [rcx + CxRbx], rbx
    mov [rcx + CxRbp], rbp
    mov [rcx + CxRsi], rsi
    mov [rcx + CxRdi], rdi
    mov [rcx + CxR12], r12
    mov [rcx + CxR13], r13
    mov [rcx + CxR14], r14
    mov [rcx + CxR15], r15

    /* Check if we're to save FPU State */
    test dword ptr [rcx + CxContextFlags], CONTEXT_FLOATING_POINT
    jz NoFpuStateSave

    movups [rcx + CxXmm6], xmm6
    movups [rcx + CxXmm7], xmm7
    movups [rcx + CxXmm8], xmm8
    movups [rcx + CxXmm9], xmm9
    movups [rcx + CxXmm10], xmm10
    movups [rcx + CxXmm11], xmm11
    movups [rcx + CxXmm12], xmm12
    movups [rcx + CxXmm13], xmm13
    movups [rcx + CxXmm14], xmm14
    movups [rcx + CxXmm15], xmm15
    stmxcsr [rcx + CxMxCsr]
    fnstcw word ptr [rcx + CxFltSave + LfControlWord]

NoFpuStateSave:
    pop rax
    mov [rcx + CxRip], rax
    mov [rcx + CxRsp], rsp
    mov rcx, rax
    /* Return 0, so the caller will know we have not switched */
    xor rax, rax
    jmp rcx
ENDFUNC

PUBLIC RtlpRestoreFiberContext
FUNC RtlpRestoreFiberContext
    .endprolog

    /* Check if we're to restore FPU State */
    test dword ptr [rcx + CxContextFlags], CONTEXT_FLOATING_POINT
    jz NoFpuStateRestore

    ldmxcsr [rcx + CxMxCsr]
    fldcw word ptr [rcx + CxFltSave + LfControlWord]
    movups xmm6, [rcx + CxXmm6]
    movups xmm7, [rcx + CxXmm7]
    movups xmm8, [rcx + CxXmm8]
    movups xmm9, [rcx + CxXmm9]
    movups xmm10, [rcx + CxXmm10]
    movups xmm11, [rcx + CxXmm11]
    movups xmm12, [rcx + CxXmm12]
    movups xmm13, [rcx + CxXmm13]
    movups xmm14, [rcx + CxXmm14]
    movups xmm15, [rcx + CxXmm15]

NoFpuStateRestore:
    mov rbx, [rcx + CxRbx]
    mov rbp, [rcx + CxRbp]
    mov rsi, [rcx + CxRsi]
    mov rdi, [rcx + CxRdi]
    mov r12, [rcx + CxR12]
    mov r13, [rcx + CxR13]
    mov r14, [rcx + CxR14]
    mov r15, [rcx + CxR15]
    mov rsp, [rcx + CxRsp]
    /* Restore EAX as well, since we use EAX to pass FIBER_CONTINUATION_STATUS::Status */
    mov rax, [ecx+CxRax]
    /* Set the 32-th bit of RAX, so the caller will know we have switched */
    bts rax, 32
    jmp qword ptr [rcx + CxRip]
ENDFUNC

END
