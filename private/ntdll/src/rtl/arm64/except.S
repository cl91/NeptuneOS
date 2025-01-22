#include <arm64asm.h>
#include <ksarm64.h>

.PROC RtlCaptureContext
    str xzr, [x0, #0x8]        /* Context->X0 */
    stp x1, x2, [x0, #0x10]    /* Context->X1,X2 */
    stp x3, x4, [x0, #0x20]    /* Context->X3,X4 */
    stp x5, x6, [x0, #0x30]    /* Context->X5,X6 */
    stp x7, x8, [x0, #0x40]    /* Context->X7,X8 */
    stp x9, x10, [x0, #0x50]   /* Context->X9,X10 */
    stp x11, x12, [x0, #0x60]  /* Context->X11,X12 */
    stp x13, x14, [x0, #0x70]  /* Context->X13,X14 */
    stp x15, x16, [x0, #0x80]  /* Context->X15,X16 */
    stp x17, x18, [x0, #0x90]  /* Context->X17,X18 */
    stp x19, x20, [x0, #0xa0]  /* Context->X19,X20 */
    stp x21, x22, [x0, #0xb0]  /* Context->X21,X22 */
    stp x23, x24, [x0, #0xc0]  /* Context->X23,X24 */
    stp x25, x26, [x0, #0xd0]  /* Context->X25,X26 */
    stp x27, x28, [x0, #0xe0]  /* Context->X27,X28 */
    stp x29, xzr, [x0, #0xf0]  /* Context->Fp,Lr */
    mov x1, sp
    stp x1, x30, [x0, #0x100]  /* Context->Sp,Pc */
    /* RtlpSaveFpuContext does not modify x0--x29, so we can use
     * x1 as a non-volatile register here. */
    mov x1, x30
    bl RtlpSaveFpuContext
    mov x30, x1
    mov w1, #0x400000          /* CONTEXT_ARM64 */
    movk w1, #0x7              /* CONTEXT_FULL */
    str w1, [x0]               /* Context->ContextFlags */
    mrs x1, NZCV
    str w1, [x0, #0x4]         /* Context->Cpsr */
    mrs x1, FPCR
    str w1, [x0, #0x310]       /* Context->Fpcr */
    mrs x1, FPSR
    str w1, [x0, #0x314]       /* Context->Fpsr */
    ret
.ENDP

.PROC DbgBreakPoint
    brk #0xf000
    ret
    nop; nop; nop; nop; nop; nop; nop
    nop; nop; nop; nop; nop; nop; nop
.ENDP

.PROC __C_ExecuteExceptionFilter
    stp x29, x30, [sp, #-96]!
    .seh_save_fplr_x 96
    stp x19, x20, [sp, #16]
    .seh_save_regp x19, 16
    stp x21, x22, [sp, #32]
    .seh_save_regp x21, 32
    stp x23, x24, [sp, #48]
    .seh_save_regp x23, 48
    stp x25, x26, [sp, #64]
    .seh_save_regp x25, 64
    stp x27, x28, [sp, #80]
    .seh_save_regp x27, 80
    .seh_endprologue
    ldp x19, x20, [x3, #0] /* nonvolatile regs */
    ldp x21, x22, [x3, #16]
    ldp x23, x24, [x3, #32]
    ldp x25, x26, [x3, #48]
    ldp x27, x28, [x3, #64]
    ldr x1, [x3, #80]      /* x29 = frame */
    blr x2                 /* filter */
    ldp x19, x20, [sp, #16]
    ldp x21, x22, [sp, #32]
    ldp x23, x24, [sp, #48]
    ldp x25, x26, [sp, #64]
    ldp x27, x28, [sp, #80]
    ldp x29, x30, [sp], #96
    ret
.ENDP

.PROC RtlpInvokeCallback
    .seh_context
    .seh_endprologue
    blr x1
    str x0, [sp, CONTEXT_PC] /* Context->Pc */
    mov x0, sp
    mov w1, #0
    b NtContinue
.ENDP

.PROC RtlpCallConsolidateCallback
    stp x29, x30, [sp, #-16]!
    .seh_save_fplr_x 16
    sub sp, sp, #0x390
    .seh_stackalloc 0x390
    .seh_endprologue
    mov x4, sp
    /* Copy the context onto the stack */
    mov x5, #0x390/16
1:  ldp x6, x7, [x0], #16
    stp x6, x7, [x4], #16
    subs x5, x5, #1
    b.ne 1b
    mov x0, x2
    b RtlpInvokeCallback
.ENDP

.PROC RtlpSaveFpuContext
    stp q0,  q1,  [x0, #0x110] /* Context->V[0-1] */
    stp q2,  q3,  [x0, #0x130] /* Context->V[2-3] */
    stp q4,  q5,  [x0, #0x150] /* Context->V[4-5] */
    stp q6,  q7,  [x0, #0x170] /* Context->V[6-7] */
    stp q8,  q9,  [x0, #0x190] /* Context->V[8-9] */
    stp q10, q11, [x0, #0x1b0] /* Context->V[10-11] */
    stp q12, q13, [x0, #0x1d0] /* Context->V[12-13] */
    stp q14, q15, [x0, #0x1f0] /* Context->V[14-15] */
    stp q16, q17, [x0, #0x210] /* Context->V[16-17] */
    stp q18, q19, [x0, #0x230] /* Context->V[18-19] */
    stp q20, q21, [x0, #0x250] /* Context->V[20-21] */
    stp q22, q23, [x0, #0x270] /* Context->V[22-23] */
    stp q24, q25, [x0, #0x290] /* Context->V[24-25] */
    stp q26, q27, [x0, #0x2b0] /* Context->V[26-27] */
    stp q28, q29, [x0, #0x2d0] /* Context->V[28-29] */
    stp q30, q31, [x0, #0x2f0] /* Context->V[30-31] */
    ret
.ENDP

.PROC RtlpRestoreFpuContext
    ldp q0,  q1,  [x0, #0x110] /* Context->V[0-1] */
    ldp q2,  q3,  [x0, #0x130] /* Context->V[2-3] */
    ldp q4,  q5,  [x0, #0x150] /* Context->V[4-5] */
    ldp q6,  q7,  [x0, #0x170] /* Context->V[6-7] */
    ldp q8,  q9,  [x0, #0x190] /* Context->V[8-9] */
    ldp q10, q11, [x0, #0x1b0] /* Context->V[10-11] */
    ldp q12, q13, [x0, #0x1d0] /* Context->V[12-13] */
    ldp q14, q15, [x0, #0x1f0] /* Context->V[14-15] */
    ldp q16, q17, [x0, #0x210] /* Context->V[16-17] */
    ldp q18, q19, [x0, #0x230] /* Context->V[18-19] */
    ldp q20, q21, [x0, #0x250] /* Context->V[20-21] */
    ldp q22, q23, [x0, #0x270] /* Context->V[22-23] */
    ldp q24, q25, [x0, #0x290] /* Context->V[24-25] */
    ldp q26, q27, [x0, #0x2b0] /* Context->V[26-27] */
    ldp q28, q29, [x0, #0x2d0] /* Context->V[28-29] */
    ldp q30, q31, [x0, #0x2f0] /* Context->V[30-31] */
    ret
.ENDP
