/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <kernel/gen_config.h>
#include <elfloader/gen_config.h>

#include <assembler.h>
#include <armv/assembler.h>

.extern non_boot_core

#if CONFIG_MAX_NUM_NODES > 1
BEGIN_FUNC(imx_non_boot)
    /* Invalidate caches before proceeding... */
    mov     r0, #0
    mcr     IIALL(r0)
    dcache  isw

    b       non_boot_core
END_FUNC(imx_non_boot)

BEGIN_FUNC(non_boot_core)
    /* Disable Async aborts that might be pending from bootloader */
    cpsid   ifa

    /* Enable SMP */
    mrc     ACTLR(r0)
    orr     r0, r0, #(1 << 6)       /* enable SMP bit   */
#ifdef CONFIG_ARM_CORTEX_A9
    orr     r0, r0, #1              /* enable FW bit    */
#endif
    mcr     ACTLR(r0)

    ldr     r2, =smp_aps_index
    ldr     r3, =core_stack_alloc - 0x10

    /* Get stack index */
    mov     r0, r2
1:  ldrex   r1, [r0]
    add     r1, r1, #1
    strex   r2, r1, [r0]
    teq     r2, #0
    bne     1b

    /* Set up stack */
    mov     r0, #0x1000
    mul     r1, r0
    add     r3, r1
    mov     sp, r3
    b       non_boot_main
END_FUNC(non_boot_core)
#endif /* CONFIG_MAX_NUM_NODES */

