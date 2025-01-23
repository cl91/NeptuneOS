/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <kernel/gen_config.h>
#include <assembler.h>
#include <armv/assembler.h>

#ifdef CONFIG_ARM_PA_SIZE_BITS_40
#define TCR_PS TCR_PS_1T
#else
#define TCR_PS TCR_PS_16T
#endif

.text

.extern flush_dcache
.extern invalidate_dcache
.extern invalidate_icache
.extern _boot_pgd_down

BEGIN_FUNC(disable_caches_hyp)
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    bl      flush_dcache
    disable_id_cache sctlr_el2, x9
    ldp     x29, x30, [sp], #16
    ret
END_FUNC(disable_caches_hyp)

BEGIN_FUNC(leave_hyp)
    /* We call nested functions, follow the ABI. */
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp

    bl      flush_dcache

    /* Ensure I-cache, D-cache and mmu are disabled for EL2/Stage1 */
    disable_mmu sctlr_el2, x9

    /*
     * Invalidate the local I-cache so that any instructions fetched
     * speculatively are discarded.
     */
    bl      invalidate_icache

    /* Ensure I-cache, D-cache and mmu are disabled for EL1/Stage2 */
    mov     x9, #(1 << 31)
    msr     hcr_el2, x9

    /* Ensure traps to EL2 are disabled */
    mov     x9, #0x33ff
    msr     cptr_el2, x9
    msr     hstr_el2, xzr
    msr     vttbr_el2, xzr

    /* Ensure I-cache, D-cache and mmu are disabled for EL1/Stage1 */
    disable_mmu sctlr_el1 , x9

    mov     x9, #(PSR_F_BIT | PSR_I_BIT | PSR_A_BIT | PSR_D_BIT | PSR_MODE_EL1h)
    msr     spsr_el2, x9

    /* Let's the caller use our stack, in case it needs to pop something */
    ldp     x29, x30, [sp], #16
    mov     x10, sp
    msr     sp_el1, x10
    msr     elr_el2, x30
    eret
END_FUNC(leave_hyp)

BEGIN_FUNC(arm_enable_hyp_mmu)
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp

    bl      flush_dcache

    disable_mmu sctlr_el2, x8

    bl      invalidate_icache

    /*
     *   DEVICE_nGnRnE      000     00000000
     *   DEVICE_nGnRE       001     00000100
     *   DEVICE_GRE         010     00001100
     *   NORMAL_NC          011     01000100
     *   NORMAL             100     11111111
     *   NORMAL_WT          101     10101010
     */
    ldr     x5, =MAIR(0x00, MT_DEVICE_nGnRnE) | \
                 MAIR(0x04, MT_DEVICE_nGnRE) | \
                 MAIR(0x0c, MT_DEVICE_GRE) | \
                 MAIR(0x44, MT_NORMAL_NC) | \
                 MAIR(0xff, MT_NORMAL) | \
                 MAIR(0xaa, MT_NORMAL_WT)
    msr     mair_el2, x5
    ldr     x8, =TCR_T0SZ(48) | TCR_IRGN0_WBWC | TCR_ORGN0_WBWC | TCR_SH0_ISH | TCR_TG0_4K | TCR_PS | TCR_EL2_RES1
    msr     tcr_el2, x8
    isb

    adrp    x8, _boot_pgd_down
    msr     ttbr0_el2, x8
    isb

    tlbi    alle2is
    dsb     ish
    isb

    enable_mmu  sctlr_el2, x8
    ic  ialluis
    dsb ish
    isb
    tlbi    alle2is
    dsb     ish
    isb
    ldp     x29, x30, [sp], #16
    ret
END_FUNC(arm_enable_hyp_mmu)
