/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <kernel/gen_config.h>
#include <elfloader/gen_config.h>
#include <elfloader_common.h>

#include <devices_gen.h>
#include <drivers/common.h>
#include <drivers/smp.h>

#include <printf.h>
#include <types.h>
#include <scu.h>
#include <abort.h>
#include <armv/machine.h>

#define REG(base, offs) ((volatile uint32_t *)(((uintptr_t)base) + (offs)))

#define CPU_JUMP_PTR              0xFFFFFFF0

/*
 * A9_CPU_RST_CTRL Register definitions.
 * See TRM B.28 System Level Control Registers (slcr)
 */
#define A9_CPU_RST_CTRL     0x44
#define PERI_RST_BIT        8
#define A9_CLKSTOPx_BIT(x)  (4 + (x))
#define A9_RSTx_BIT(x)      (0 + (x))

UNUSED static void *get_scu_base(void)
{
    void *scu = NULL;
#if CONFIG_ARCH_AARCH32
    asm("mrc p15, 4, %0, c15, c0, 0" : "=r"(scu));
#else
    abort();
#endif
    return scu;
}


static int smp_zynq7000_cpu_on(UNUSED struct elfloader_device *dev,
                               UNUSED struct elfloader_cpu *cpu, UNUSED void *entry, UNUSED void *stack)
{
#if CONFIG_MAX_NUM_NODES > 1
    volatile void *mmio = dev->region_bases[0];
    volatile word_t *jump_ptr = (volatile word_t *)CPU_JUMP_PTR;
    secondary_data.entry = entry;
    secondary_data.stack = stack;
    /* stop core - see TRM 3.7 Application Processing Unit (APU) Reset */
    *REG(mmio, A9_CPU_RST_CTRL) |= BIT(A9_RSTx_BIT(cpu->cpu_id));
    dsb();
    *REG(mmio, A9_CPU_RST_CTRL) |= BIT(A9_CLKSTOPx_BIT(cpu->cpu_id));
    dsb();
    /* set where core should jump to when it's woken up */
    *jump_ptr = (word_t)secondary_startup;
    /* start core */
    *REG(mmio, A9_CPU_RST_CTRL) &= ~BIT(A9_RSTx_BIT(cpu->cpu_id));
    dsb();
    *REG(mmio, A9_CPU_RST_CTRL) &= ~BIT(A9_CLKSTOPx_BIT(cpu->cpu_id));
    dsb();
    /* the other core is in WFE, we need to wake it */
    asm volatile("sev");

    return 0;
#else
    return -1;
#endif
}

static int smp_zynq7000_init(UNUSED struct elfloader_device *dev,
                             UNUSED void *match_data)
{
#if CONFIG_MAX_NUM_NODES > 1
    void *scu = get_scu_base();
    scu_enable(scu);
    smp_register_handler(dev);
#endif
    return 0;
}


static const struct dtb_match_table smp_zynq7000_matches[] = {
    { .compatible = "xlnx,zynq-reset" },
    { .compatible = NULL /* sentinel */ },
};

static const struct elfloader_smp_ops smp_zynq7000_ops = {
    .enable_method = NULL,
    .cpu_on = &smp_zynq7000_cpu_on,
};

static const struct elfloader_driver smp_zynq7000 = {
    .match_table = smp_zynq7000_matches,
    .type = DRIVER_SMP,
    .init = &smp_zynq7000_init,
    .ops = &smp_zynq7000_ops,
};

ELFLOADER_DRIVER(smp_zynq7000);
