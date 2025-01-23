/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <kernel/gen_config.h>
#include <elfloader/gen_config.h>

#include <assembler.h>
#include <armv/assembler.h>

.text

.extern _boot_pd

BEGIN_FUNC(invalidate_dcache)
    stmfd   sp!, {r4-r11,lr}
    dcache  isw
    ldmfd   sp!, {r4-r11,pc}
END_FUNC(invalidate_dcache)

BEGIN_FUNC(invalidate_icache)
    mcr     IIALL(r1)
    bx      lr
END_FUNC(invalidate_icache)

BEGIN_FUNC(flush_dcache)
    stmfd   sp!, {r4-r11,lr}
    dcache  cisw
    ldmfd   sp!, {r4-r11,pc}
END_FUNC(flush_dcache)

/*
 * Enable the ARM MMU.
 *
 * It is expected that the code of this function will be mapped 1:1
 * virtual/physical in the pagetable we activate.
 */
BEGIN_FUNC(arm_enable_mmu)
    stmfd   sp!, {lr}

    /* Clean D-Cache if enabled */
    mrc     SCTLR(r1)
    and     r1, r1, #(1 << 2)
    cmp     r1, #0
    beq     1f
    bl      flush_dcache
1:
    /* Ensure I-cache, D-cache and mmu are disabled. */
    mrc     SCTLR(r1)
    bic     r1, r1, #(1 << 12)      /* Disable I-cache */
    bic     r1, r1, #(1 << 2)       /* Disable D-Cache */
    bic     r1, r1, #(1 << 0)       /* Disable MMU     */
    mcr     SCTLR(r1)

    /* invalidate caches. */
    bl      invalidate_dcache
    bl      invalidate_icache

    /* Set up TTBR0, enable caching of pagetables. */
    bl      get_boot_pd
    orr     r1, r0, #0x19
    mcr     TTBR0(r1)
    mcr     TLBIALL(r1)

    /* Setup client to only have access to domain 0, and setup the DACR. */
    mov     r1, #1
    mcr     DACR(r1)

    /* Setup misc MMU. */
    mov     r1, #0
    mcr     CONTEXTIDR(r1)  /* set ASID to 0    */
    mcr     TTBCR(r1)       /* set TTBCR to 0   */
    mcr     BPIALL(r1)      /* flush branch target cache */
    isb

    /* Enable MMU, D-cache, and I-cache. */
    mrc     SCTLR(r0)
    orr     r0, r0, #(1 << 13)      /* selects the base address of the exception vectors */
    orr     r0, r0, #(1 << 12)      /* Enable I-cache */
    orr     r0, r0, #(1 << 2)       /* Enable D-cache */
    orr     r0, r0, #(1 << 0)       /* Enable MMU */
    mcr     SCTLR(r0)

    /* Enable/disable Async aborts to drain pending bootloader aborts */
    cpsie   a
    dsb
    isb
    cpsid   a

    ldmfd   sp!, {pc}
END_FUNC(arm_enable_mmu)

BEGIN_FUNC(arm_disable_dcaches)
    stmfd   sp!, {lr}

    /* Clean D-Cache if enabled */
    mrc     SCTLR(r1)
    and     r1, r1, #(1 << 2)
    cmp     r1, #0
    beq     1f
    bl      flush_dcache
1:
    /* disable D-cache disabled. */
    mrc     SCTLR(r1)
    bic     r1, r1, #(1 << 2)       /* Disable D-Cache */
    mcr     SCTLR(r1)

    /* invalidate dcaches. */
    bl      invalidate_dcache

    ldmfd   sp!, {pc}
END_FUNC(arm_disable_dcaches)
