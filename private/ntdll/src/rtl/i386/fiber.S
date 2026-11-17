/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS system libraries
 * FILE:        dll/win32/kernel32/client/i386/fiber.S
 * PURPOSE:     Fiber context switch code for the x86 architecture
 * PROGRAMMERS: Alex Ionescu (alex@relsoft.net)
 *              KJK::Hyperion <noog@libero.it>
 */

#include <x86asm.h>
#include <ks386.h>
.intel_syntax noprefix

.code

PUBLIC @RtlpCaptureFiberContext@4
FUNC @RtlpCaptureFiberContext@4
    FPO(0, 0, 0, 0, 0, FRAME_FPO)

    /* Save the non-volatile registers */
    mov [ecx+CONTEXT_EBX], ebx
    mov [ecx+CONTEXT_ESI], esi
    mov [ecx+CONTEXT_EDI], edi
    mov [ecx+CONTEXT_EBP], ebp

    /* Pop the return address and save into the context */
    pop eax
    mov [ecx+CONTEXT_EIP], eax
    mov [ecx+CONTEXT_ESP], esp

    /* Check if we're to save FPU State */
    test dword ptr [ecx+CONTEXT_FLAGS], CONTEXT_FLOATING_POINT
    jz NoFpuStateSave

    /* Save the FPU State (Status and Control) */
    fnstsw [ecx+CONTEXT_FLOAT_SAVE_STATUS_WORD]
    fnstcw [ecx+CONTEXT_FLOAT_SAVE_CONTROL_WORD]

    /* Save the SIMD MXCSR State Save */
    stmxcsr [ecx+CONTEXT_DR6]

NoFpuStateSave:
    mov ecx, eax
    /* Zero edx, so the caller will know we have not switched */
    xor edx, edx
    /* Also zero eax so the caller does not get a stale value */
    xor eax, eax
    /* Go back to where we came from */
    jmp ecx

ENDFUNC


PUBLIC @RtlpRestoreFiberContext@4
FUNC @RtlpRestoreFiberContext@4
    FPO(0, 0, 0, 0, 0, FRAME_FPO)

    /* Restore non-volatile registers */
    mov esi, [ecx+CONTEXT_ESI]
    mov edi, [ecx+CONTEXT_EDI]
    mov ebx, [ecx+CONTEXT_EBX]
    mov ebp, [ecx+CONTEXT_EBP]
    mov esp, [ecx+CONTEXT_ESP]

    /* Restore EAX as well, since we use EAX to pass FIBER_CONTINUATION_STATUS::Status */
    mov eax, [ecx+CONTEXT_EAX]

    /* Restore FPU State */
    test dword ptr [ecx+CONTEXT_FLAGS], CONTEXT_FLOATING_POINT
    jz NoFpuStateRestore

    /* Load the new status word */
    mov word ptr [ecx+CONTEXT_FLOAT_SAVE_TAG_WORD], HEX(FFFF)
    fldenv [ecx+CONTEXT_FLOAT_SAVE_CONTROL_WORD]
    ldmxcsr [ecx+CONTEXT_DR6]

NoFpuStateRestore:
    mov ecx, [ecx+CONTEXT_EIP]
    /* Set EDX to 1, so the caller will know we have switched */
    xor edx, edx
    inc edx
    jmp ecx

ENDFUNC

END
/* EOF */
