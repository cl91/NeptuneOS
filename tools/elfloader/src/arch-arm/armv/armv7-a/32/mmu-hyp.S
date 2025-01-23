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

.extern _lpae_boot_pgd
.extern flush_dcache
.extern invalidate_dcache
.extern invalidate_icache

BEGIN_FUNC(leave_hyp)
    .arch_extension virt
    ldr r0, =CPSR_SUPERVISOR
    msr spsr_hyp, r0
    msr sp_svc, sp
    msr elr_hyp, lr
    eret
END_FUNC(leave_hyp)

/*
 * Enable the ARM MMU.
 *
 * It is expected that the code of this function will be mapped 1:1
 * virtual/physical in the pagetable we activate.
 */
BEGIN_FUNC(arm_enable_hyp_mmu)
    stmfd   sp!, {lr}

    /* Clean D-Cache if enabled */
    mrc     HSCTLR(r1)
    and     r1, r1, #(1 << 2)
    cmp     r1, #0
    bleq    flush_dcache

    /* Ensure I-cache, D-cache and mmu are disabled. */
    mrc     HSCTLR(r1)
    bic     r1, r1, #(1 << 12) /* Disable I-cache */
    bic     r1, r1, #(1 << 2)  /* Disable D-Cache */
    bic     r1, r1, #(1 << 0)  /* Disable MMU */
    mcr     HSCTLR(r1)

    /* invalidate caches. */
    bl      invalidate_dcache
    bl      invalidate_icache

    /* Setup MAIR - Strongly ordered non-cachable for all index */
    mov     r1, #0
    mcr     HMAIR0(r1)
    mcr     HMAIR1(r1)

    /* Set up the page table */
    bl      get_lpae_boot_pgd
    mov     r1, #0
    mov     r2, #(1<<31)
    mcrr    HTTBR(r1,r0)
    mcr     HTCR(r2)

    /* Invalidate TLB */
    mcr     DTLBIALL(r1)

    /* Enable MMU, D-cache, and I-cache. */
    mrc     HSCTLR(r0)
    orr     r0, r0, #(1 << 2)  // enable dcache
    orr     r0, r0, #(1 << 12) // enable icache
    orr     r0, r0, #(1 << 0)  // MMU enable
    mcr     HSCTLR(r0)

#if CONFIG_MAX_NUM_NODES > 1
    /* Enable SMP */
    mrc     p15, 0, r0, c1, c0, 1
    orr     r0, r0, #(1 << 6) // enable SMP bit
    mcr     p15, 0, r0, c1, c0, 1
#endif /* CONFIG_MAX_NUM_NODES > 1 */

    ldmfd   sp!, {pc}
END_FUNC(arm_enable_hyp_mmu)
