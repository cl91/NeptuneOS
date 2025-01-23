/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/* This file is used to switch from aarch64 EL2 to aarch32 supervisor mode
 * before continuing in the aarch32 elfloader. This allows aarch32 seL4 kernel
 * configurations to be loaded from a 64bit entry point
 */
#include <assembler.h>
#include <armv/assembler.h>

.section ".text.start"

BEGIN_FUNC(_start)
    /* Clean EL2 dcache */
    dcache  cisw

    /* Ensure I-cache, D-cache and mmu are disabled for EL2/Stage1 */
    disable_mmu sctlr_el2, x9

    /*
     * Invalidate the local I-cache so that any instructions fetched
     * speculatively are discarded.
     */
    ic      iallu
    dsb     nsh
    isb

    msr     sctlr_el1, xzr
    /* Ensure traps to EL2 are disabled */
    mov     x9, #0x33ff
    msr     cptr_el2, x9
    msr     hstr_el2, xzr
    msr     mdcr_el2, xzr

    /* Set a zero VMID */
    msr     vttbr_el2, xzr

    /* Set lower level execution state to aarch32 */
    msr     hcr_el2, xzr
    mov     x17, #0
    bic     x17, x17, #(1 << 31)
    msr     hcr_el2, x17

    /* Setup spsr to return to */
    mov     x18, #(PSR_F_BIT | PSR_I_BIT | PSR_A_BIT | PSR_MODE_SVC_32)
    msr     spsr_el2, x18

    /* Set our return address to the instruction after eret. */
    adr     x19, 1f
    msr     elr_el2, x19
    eret
    1:
