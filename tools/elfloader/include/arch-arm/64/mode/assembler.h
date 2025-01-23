/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#pragma once

/* This file contains useful macros for assembly code. */

#ifdef __ASSEMBLER__

#define PSR_F_BIT         0x00000040
#define PSR_I_BIT         0x00000080
#define PSR_A_BIT         0x00000100
#define PSR_D_BIT         0x00000200

#define PSR_MODE_EL0t     0x00000000
#define PSR_MODE_EL1t     0x00000004
#define PSR_MODE_EL1h     0x00000005
#define PSR_MODE_EL2t     0x00000008
#define PSR_MODE_EL2h     0x00000009
#define PSR_MODE_SVC_32   0x00000013

#define TCR_T0SZ(x)       ((64 - (x)))
#define TCR_T1SZ(x)       ((64 - (x)) << 16)
#define TCR_TxSZ(x)       (TCR_T0SZ(x) | TCR_T1SZ(x))

#define TCR_IRGN0_WBWC    (1 << 8)
#define TCR_IRGN_NC       ((0 << 8) | (0 << 24))
#define TCR_IRGN_WBWA     ((1 << 8) | (1 << 24))
#define TCR_IRGN_WT       ((2 << 8) | (2 << 24))
#define TCR_IRGN_WBnWA    ((3 << 8) | (3 << 24))
#define TCR_IRGN_MASK     ((3 << 8) | (3 << 24))

#define TCR_ORGN0_WBWC    (1 << 10)
#define TCR_ORGN_NC       ((0 << 10) | (0 << 26))
#define TCR_ORGN_WBWA     ((1 << 10) | (1 << 26))
#define TCR_ORGN_WT       ((2 << 10) | (2 << 26))
#define TCR_ORGN_WBnWA    ((3 << 10) | (3 << 26))
#define TCR_ORGN_MASK     ((3 << 10) | (3 << 26))

#define TCR_SH0_ISH       (3 << 12)
#define TCR_SHARED        ((3 << 12) | (3 << 28))

#define TCR_TG0_4K        (0 << 14)
#define TCR_TG0_64K       (1 << 14)
#define TCR_TG1_4K        (2 << 30)
#define TCR_TG1_64K       (3 << 30)

#define TCR_PS_4G         (0 << 16)
#define TCR_PS_64G        (1 << 16)
#define TCR_PS_1T         (2 << 16)
#define TCR_PS_4T         (3 << 16)
#define TCR_PS_16T        (4 << 16)
#define TCR_PS_256T       (5 << 16)

/* bits are reserved as 1 */
#define TCR_EL2_RES1      ((1 << 23) | (1 << 31))
#define TCR_ASID16        (1 << 36)

#define MT_DEVICE_nGnRnE  0
#define MT_DEVICE_nGnRE   1
#define MT_DEVICE_GRE     2
#define MT_NORMAL_NC      3
#define MT_NORMAL         4
#define MT_NORMAL_WT      5
#define MAIR(_attr, _mt)  ((_attr) << ((_mt) * 8))

.macro enable_mmu sctlr tmp
    mrs     \tmp, \sctlr
    orr     \tmp, \tmp, #(1 << 0)
    orr     \tmp, \tmp, #(1 << 2)
    orr     \tmp, \tmp, #(1 << 12)
    msr     \sctlr, \tmp
    isb
.endm

.macro disable_mmu sctlr tmp
    mrs     \tmp, \sctlr
    bic     \tmp, \tmp, #(1 << 0)
    bic     \tmp, \tmp, #(1 << 2)
    bic     \tmp, \tmp, #(1 << 12)
    msr     \sctlr, \tmp
    isb
.endm

.macro disable_id_cache sctlr tmp
    mrs     \tmp, \sctlr
    bic     \tmp, \tmp, #(1 << 2)
    bic     \tmp, \tmp, #(1 << 12)
    msr     \sctlr, \tmp
    isb
.endm

.macro dcache op
    dsb     sy
    mrs     x0, clidr_el1
    and     x3, x0, #0x7000000
    lsr     x3, x3, #23

    cbz     x3, finished_\op
    mov     x10, #0

loop1_\op:
    add     x2, x10, x10, lsr #1
    lsr     x1, x0, x2
    and     x1, x1, #7
    cmp     x1, #2
    b.lt    skip_\op

    msr     csselr_el1, x10
    isb

    mrs     x1, ccsidr_el1
    and     x2, x1, #7
    add     x2, x2, #4
    mov     x4, #0x3ff
    and     x4, x4, x1, lsr #3
    clz     w5, w4
    mov     x7, #0x7fff
    and     x7, x7, x1, lsr #13

loop2_\op:
    mov     x9, x4

loop3_\op:
    lsl     x6, x9, x5
    orr     x11, x10, x6
    lsl     x6, x7, x2
    orr     x11, x11, x6
    dc      \op, x11
    subs    x9, x9, #1
    b.ge    loop3_\op
    subs    x7, x7, #1
    b.ge    loop2_\op

skip_\op:
    add     x10, x10, #2
    cmp     x3, x10
    b.gt    loop1_\op

finished_\op:
    mov     x10, #0
    msr     csselr_el1, x10
    dsb     sy
    isb
.endm

#else /* !__ASSEMBLER__ */
#warning "Including assembly-specific header in C code"
#endif

