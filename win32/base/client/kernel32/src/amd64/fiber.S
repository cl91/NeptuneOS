/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS system libraries
 * FILE:        dll/win32/kernel32/client/amd64/fiber.S
 * PURPOSE:     Fiber context switch code for the amd64 architecture
 * PROGRAMMER:
 */

#include "../../../../../../private/rtl/inc/x86asm.h"
#include <ksamd64.h>
.intel_syntax noprefix

EXTERN BaseThreadStartup:PROC

.code64

PUBLIC BaseFiberStartup
FUNC BaseFiberStartup
    .endprolog
    mov rax, gs:[TeFiberData]
    mov rcx, [rax + FbFiberContext + CxRcx]
    mov rdx, [rax + FbFiberContext + CxRdx]
    jmp BaseThreadStartup

ENDFUNC


PUBLIC SwitchToFiber

FUNC SwitchToFiber
    .endprolog
    mov rdx, gs:[TeSelf]
    mov rax, [rdx + TeFiberData]

    mov [rax + FbFiberContext + CxRbx], rbx
    mov [rax + FbFiberContext + CxRbp], rbp
    mov [rax + FbFiberContext + CxRsi], rsi
    mov [rax + FbFiberContext + CxRdi], rdi
    mov [rax + FbFiberContext + CxR12], r12
    mov [rax + FbFiberContext + CxR13], r13
    mov [rax + FbFiberContext + CxR14], r14
    mov [rax + FbFiberContext + CxR15], r15
    movups [rax + FbFiberContext + CxXmm6], xmm6
    movups [rax + FbFiberContext + CxXmm7], xmm7
    movups [rax + FbFiberContext + CxXmm8], xmm8
    movups [rax + FbFiberContext + CxXmm9], xmm9
    movups [rax + FbFiberContext + CxXmm10], xmm10
    movups [rax + FbFiberContext + CxXmm11], xmm11
    movups [rax + FbFiberContext + CxXmm12], xmm12
    movups [rax + FbFiberContext + CxXmm13], xmm13
    movups [rax + FbFiberContext + CxXmm14], xmm14
    movups [rax + FbFiberContext + CxXmm15], xmm15
    stmxcsr [rax + FbFiberContext + CxMxCsr]
    fnstcw word ptr [rax + FbFiberContext + CxFltSave + LfControlWord]

    mov r8, [rsp]
    mov [rax + FbFiberContext + CxRip], r8
    lea r8, [rsp + 8]
    mov [rax + FbFiberContext + CxRsp], r8

    mov r8, [rdx + TeStackLimit]
    mov [rax + FbStackLimit], r8
    mov r8d, [rdx + TeGuaranteedStackBytes]
    mov [rax + FbGuaranteedStackBytes], r8d
    mov r8, [rdx + TeActivationContextStackPointer]
    mov [rax + FbActivationContextStackPointer], r8
    mov r8, [rdx + TeFlsData]
    mov [rax + FbFlsData], r8

    mov [rdx + TeFiberData], rcx
    mov r8, [rcx + FbStackBase]
    mov [rdx + TeStackBase], r8
    mov r8, [rcx + FbStackLimit]
    mov [rdx + TeStackLimit], r8
    mov r8, [rcx + FbDeallocationStack]
    mov [rdx + TeDeallocationStack], r8
    mov r8d, [rcx + FbGuaranteedStackBytes]
    mov [rdx + TeGuaranteedStackBytes], r8d
    mov r8, [rcx + FbActivationContextStackPointer]
    mov [rdx + TeActivationContextStackPointer], r8
    mov r8, [rcx + FbFlsData]
    mov [rdx + TeFlsData], r8

    ldmxcsr [rcx + FbFiberContext + CxMxCsr]
    fldcw word ptr [rcx + FbFiberContext + CxFltSave + LfControlWord]
    movups xmm6, [rcx + FbFiberContext + CxXmm6]
    movups xmm7, [rcx + FbFiberContext + CxXmm7]
    movups xmm8, [rcx + FbFiberContext + CxXmm8]
    movups xmm9, [rcx + FbFiberContext + CxXmm9]
    movups xmm10, [rcx + FbFiberContext + CxXmm10]
    movups xmm11, [rcx + FbFiberContext + CxXmm11]
    movups xmm12, [rcx + FbFiberContext + CxXmm12]
    movups xmm13, [rcx + FbFiberContext + CxXmm13]
    movups xmm14, [rcx + FbFiberContext + CxXmm14]
    movups xmm15, [rcx + FbFiberContext + CxXmm15]
    mov rbx, [rcx + FbFiberContext + CxRbx]
    mov rbp, [rcx + FbFiberContext + CxRbp]
    mov rsi, [rcx + FbFiberContext + CxRsi]
    mov rdi, [rcx + FbFiberContext + CxRdi]
    mov r12, [rcx + FbFiberContext + CxR12]
    mov r13, [rcx + FbFiberContext + CxR13]
    mov r14, [rcx + FbFiberContext + CxR14]
    mov r15, [rcx + FbFiberContext + CxR15]
    mov rsp, [rcx + FbFiberContext + CxRsp]
    jmp qword ptr [rcx + FbFiberContext + CxRip]
ENDFUNC

END
