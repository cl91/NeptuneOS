/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS system libraries
 * FILE:        private/ntdll/src/rtl/arm64/fiber.S
 * PURPOSE:     Fiber context switch code for the arm64 architecture
 * PROGRAMMER:
 */

#include <arm64asm.h>
#include <ksarm64.h>

.PROC RtlpCaptureFiberContext
    /* Save the non-volatile integer registers */
    stp x19, x20, [x0, #CONTEXT_X19]
    stp x21, x22, [x0, #CONTEXT_X21]
    stp x23, x24, [x0, #CONTEXT_X23]
    stp x25, x26, [x0, #CONTEXT_X25]
    stp x27, x28, [x0, #CONTEXT_X27]
    stp x29, x30, [x0, #CONTEXT_FP]

    /* Check if we're to save FPU State */
    ldr w9, [x0, #CONTEXT_FLAGS]
    mov w10, #CONTEXT_FLOATING_POINT_WORD0
    movk w10, #CONTEXT_FLOATING_POINT_WORD1, lsl #16
    tst w9, w10
    b.eq .LNoFpuStateSave

    /* Only the low 64 bits of V8-V15 are non-volatile */
    stp d8, d9, [x0, #CONTEXT_V8]
    stp d10, d11, [x0, #CONTEXT_V10]
    stp d12, d13, [x0, #CONTEXT_V12]
    stp d14, d15, [x0, #CONTEXT_V14]

    /* Save the floating-point control and status registers */
    mrs x9, FPCR
    str w9, [x0, #CONTEXT_FPCR]
    mrs x9, FPSR
    str w9, [x0, #CONTEXT_FPSR]

.LNoFpuStateSave:
    /* The link register is the continuation after this call */
    str x30, [x0, #CONTEXT_PC]
    mov x9, sp
    str x9, [x0, #CONTEXT_SP]

    /* Return 0, so the caller will know we have not switched */
    mov x0, #0
    ret
.ENDP

.PROC RtlpRestoreFiberContext
    /* Check if we're to restore FPU State */
    ldr w9, [x0, #CONTEXT_FLAGS]
    mov w10, #CONTEXT_FLOATING_POINT_WORD0
    movk w10, #CONTEXT_FLOATING_POINT_WORD1, lsl #16
    tst w9, w10
    b.eq .LNoFpuStateRestore

    /* Restore the floating-point control and status registers */
    ldr w9, [x0, #CONTEXT_FPCR]
    msr FPCR, x9
    ldr w9, [x0, #CONTEXT_FPSR]
    msr FPSR, x9

    /* Restore the non-volatile floating-point registers */
    ldp d8, d9, [x0, #CONTEXT_V8]
    ldp d10, d11, [x0, #CONTEXT_V10]
    ldp d12, d13, [x0, #CONTEXT_V12]
    ldp d14, d15, [x0, #CONTEXT_V14]

.LNoFpuStateRestore:
    /* Restore the non-volatile integer registers */
    ldp x19, x20, [x0, #CONTEXT_X19]
    ldp x21, x22, [x0, #CONTEXT_X21]
    ldp x23, x24, [x0, #CONTEXT_X23]
    ldp x25, x26, [x0, #CONTEXT_X25]
    ldp x27, x28, [x0, #CONTEXT_X27]
    ldp x29, x30, [x0, #CONTEXT_FP]

    /* Switch to the captured stack and continuation */
    ldr x9, [x0, #CONTEXT_SP]
    mov sp, x9
    ldr x9, [x0, #CONTEXT_PC]

    /* Restore X0 as well, since we use the low 32 bits of X0 to pass
     * FIBER_CONTINUATION_STATUS::Status */
    ldr x0, [x0, #CONTEXT_X0]
    /* Set the 32-th bit of X0, so the caller will know we have switched */
    mov w1, #1
    orr x0, x0, x1, lsl #32
    br x9
.ENDP

/* EOF */
