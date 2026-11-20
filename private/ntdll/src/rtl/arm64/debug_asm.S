/*
 * PROJECT:     ReactOS Run-Time Library
 * LICENSE:     GPL-3.0-or-later
 * PURPOSE:     ARM64 debug service entry points
 */

#include <arm64asm.h>
#include <ksarm64.h>

.text
.align 4

.global DbgUserBreakPoint
DbgUserBreakPoint:

.global DbgBreakPoint
.seh_proc DbgBreakPoint
DbgBreakPoint:
.seh_endprologue
    brk     #0xf000
    ret
    nop; nop; nop; nop; nop; nop; nop
    nop; nop; nop; nop; nop; nop; nop
.seh_endproc

.global RtlpBreakWithStatusInstruction
RtlpBreakWithStatusInstruction:

.global DbgBreakPointWithStatus
.seh_proc DbgBreakPointWithStatus
DbgBreakPointWithStatus:
.seh_endprologue
    brk     #0xf000
    ret
.seh_endproc

/*
 * ULONG NTAPI DebugService(
 *     ULONG Service, PVOID Argument1, PVOID Argument2,
 *     PVOID Argument3, PVOID Argument4);
 *
 * The ARM64 debug-service ABI expects:
 *   x0 = service, x1-x4 = service arguments.
 */
.global DebugService
.seh_proc DebugService
DebugService:
.seh_endprologue
    brk     #0xf002
    ret
.seh_endproc

/*
 * VOID NTAPI DebugService2(PVOID Argument1, PVOID Argument2, ULONG Service);
 */
.global DebugService2
.seh_proc DebugService2
DebugService2:
.seh_endprologue
    mov     x3, x2
    mov     x2, x1
    mov     x1, x0
    mov     x0, x3
    brk     #0xf002
    ret
.seh_endproc
