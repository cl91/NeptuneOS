/*
 * COPYRIGHT:         See COPYING in the top level directory
 * PROJECT:           ReactOS Run-Time Library
 * PURPOSE:           Debug Routines
 * FILE:              lib/rtl/amd64/debug_asm.S
 * PROGRAMER:         Timo Kreuzer (timo.kreuzer@reactos.org)
 */

#include <asm.h>
.intel_syntax noprefix

/* GLOBALS ****************************************************************/

.global DbgBreakPoint
.global DbgBreakPointWithStatus
.global DbgUserBreakPoint
.global DebugService
.global DebugService2
.global DbgBreakPointNoBugCheck
.global RtlpBreakWithStatusInstruction

/* FUNCTIONS ***************************************************************/

.code64

.PROC DbgBreakPointNoBugCheck
    .endprolog
    int 3
    ret
.ENDP

DbgUserBreakPoint:
.PROC DbgBreakPoint
    .endprolog
    int 3
    ret
.ENDP

.PROC DbgBreakPointWithStatus
    .endprolog
    mov eax, ecx
.ENDP

.PROC RtlpBreakWithStatusInstruction
    .endprolog
    int 3
    ret
.ENDP

DebugService2:

    /* Pass the service number in eax */
    mov rax, r8
    int HEX(2D)
    int 3
    ret


/******************************************************************************
 * NTSTATUS NTAPI DebugService(
 *     IN ULONG Service,    // <rcx> = [rsp + 8]
 *     IN PVOID Buffer,     // <rdx> = [rsp + 16]
 *     IN ULONG Length,     // <r8>  = [rsp + 24]
 *     IN PVOID Argument1,  // <r9>  = [rsp + 32]
 *     IN PVOID Argument2); //         [rsp + 40]
 */
DebugService:

    /* Prepare registers for interrupt */
    mov eax, ecx       // Service
    mov rcx, rdx       // Buffer
    mov edx, r8d       // Length
    mov r8, r9         // Argument1
    mov r9, [rsp + 40] // Argument2

    /* Call the Interrupt */
    int HEX(2D)
    int 3

   /* Return */
    ret
