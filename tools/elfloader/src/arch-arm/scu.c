/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright: Linux Kernel team
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * The code in here is loosely derived from the Linux kernel
 */

/* Driver for the ARM Snoop Control Unit (SCU) used on multicore systems */

#include <kernel/gen_config.h>
#include <elfloader/gen_config.h>

#if CONFIG_MAX_NUM_NODES > 1

#include <types.h>
#include <cpuid.h>

#include <elfloader.h>

#define SCU_CTRL 0
#define SCU_CONFIG 1

/* Enable the SCU */
void scu_enable(void *_scu_base)
{
    uint32_t scu_ctrl;
    volatile uint32_t *scu_base = (volatile uint32_t *)_scu_base;

#ifdef CONFIG_ARM_ERRATA_764369
    /* Cortex-A9 only */
    if ((read_cpuid_id() & 0xff0ffff0) == 0x410fc090) {
        scu_ctrl = scu_base[0x30 / 4];
        if (!(scu_ctrl & 1)) {
            scu_base[0x30 / 4] = scu_ctrl | 0x1;
        }
    }
#endif

    scu_ctrl = scu_base[SCU_CTRL];
    /* already enabled? */
    if (scu_ctrl & 1) {
        return;
    }

    scu_ctrl |= 1;
    scu_base[SCU_CTRL] = scu_ctrl;

    /*
     * Ensure that the data accessed by CPU0 before the SCU was
     * initialised is visible to the other CPUs.
     */
    flush_dcache();
}

/*
 * Get the number of CPU cores from the SCU configuration
 */
unsigned int scu_get_core_count(void *_scu_base)
{
    volatile uint32_t *scu_base = (volatile uint32_t *)_scu_base;
    unsigned int ncores = (unsigned int)scu_base[SCU_CONFIG];
    return (ncores & 0x03) + 1;
}

#endif /* CONFIG_MAX_NUM_NODES > 1 */
