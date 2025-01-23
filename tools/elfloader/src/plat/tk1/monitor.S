/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */


#include <kernel/gen_config.h>
#include <elfloader/gen_config.h>

#ifndef CONFIG_ARM_MONITOR_HOOK
#error This file is for CONFIG_ARM_MONITOR_HOOK only
#endif

#define VECTOR_BASE     0xa7f00000
#define STACK_TOP       (VECTOR_BASE + (1 << 20) - 0x10)

/* vector table for monitor mode
 * 0x00: not used
 * 0x04: not used
 * 0x08: secure monitor call
 * 0x0c: prefetch abort
 * 0x10: data abort
 * 0x14: not used
 * 0x18: IRQ interrupt
 * 0x1c: FIQ interrupt
 */

.global arm_monitor_vector
.global arm_monitor_vector_end
.global smc_handler
.global smc_halt

/* pc contains the current instruction + 8 bytes
 * use pc-relative addressing so we can copy the
 * table. only the offset 0x08 is set up to call
 * smc_handler, other offsets halt the system.
 */

arm_monitor_vector:
    ldr pc, [pc, #28]
    ldr pc, [pc, #24]
    ldr pc, [pc, #16]
    ldr pc, [pc, #16]
    ldr pc, [pc, #12]
    ldr pc, [pc, #8]
    ldr pc, [pc, #4]
    ldr pc, [pc, #0]

smc_handler_addr:
.word   VECTOR_BASE + (smc_handler - arm_monitor_vector)
smc_halt_addr:
.word   VECTOR_BASE + (smc_halt - arm_monitor_vector)
smc_stack:
.word   STACK_TOP

/* r0: the start physical address for the code that the
 * caller wants to execute in monitor mode. I know, a huge
 * security hole. WARNING: the code to be executed should
 * not reference memory locations !!!
 */
smc_handler:
    /* always have a valid stack */
    ldr sp, [pc, #-12]
    push {lr}
    blx  r0
    mrc p15, 0, r12, c1, c1, 0
    /* set the NS bit */
    orr r12, r12, #1
    mcr p15, 0, r12, c1, c1, 0
    pop {lr}
    movs pc, lr

/* for all other exceptions, just hang */
smc_halt:
    ldr pc, [pc, #-48]

arm_monitor_vector_end:
