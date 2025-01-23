/*
 * Copyright Linux Kernel team
 * Copyright 2020, HENSOLDT Cyber GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * The code in here is loosely derived from the Linux kernel
 */

#include <kernel/gen_config.h>
#include <elfloader/gen_config.h>
#include <elfloader_common.h>

#include <devices_gen.h>
#include <drivers/common.h>
#include <drivers/smp.h>

#include <printf.h>
#include <armv/machine.h>
#include <scu.h>
#include <abort.h>

#define REG(base, offs) ((volatile word_t *)(((uintptr_t)base) + (offs)))

#define SRC_SCR             0x000
#define SRC_GPR1            0x020
#define BP_SRC_SCR_WARM_RESET_ENABLE    0
#define BP_SRC_SCR_CORE1_RST        14
#define BP_SRC_SCR_CORE1_ENABLE     22


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

UNUSED static void src_init(volatile void *mmio)
{
    uint32_t val;
    val = *REG(mmio, SRC_SCR);
    val &= ~(1 << BP_SRC_SCR_WARM_RESET_ENABLE);
    *REG(mmio, SRC_SCR) = val;
}

static int smp_imx6_cpu_on(UNUSED struct elfloader_device *dev,
                           UNUSED struct elfloader_cpu *cpu, UNUSED void *entry, UNUSED void *stack)
{
#if CONFIG_MAX_NUM_NODES > 1
    volatile void *mmio = dev->region_bases[0];
    secondary_data.entry = entry;
    secondary_data.stack = stack;
    *REG(mmio, SRC_GPR1 + (cpu->cpu_id * 8)) = (word_t)secondary_startup;
    dsb();

    if (cpu->cpu_id == 0) {
        /* there is no core0_enable bit in the SCR register */
        printf("error: cannot power on CPU 0!\n");
        return -1;
    }

    uint32_t mask = 1 << (BP_SRC_SCR_CORE1_ENABLE + (cpu->cpu_id - 1));
    *REG(mmio, SRC_SCR) |= mask;
    return 0;
#else
    return -1;
#endif
}

static int smp_imx6_init(UNUSED struct elfloader_device *dev,
                         UNUSED void *match_data)
{
#if CONFIG_MAX_NUM_NODES > 1
    void *scu = get_scu_base();
    scu_enable(scu);
    src_init(dev->region_bases[0]);
    smp_register_handler(dev);
#endif
    return 0;
}


static const struct dtb_match_table smp_imx6_matches[] = {
    { .compatible = "fsl,imx6q-src" },
    { .compatible = "fsl,imx6sx-src" },
    { .compatible = NULL /* sentinel */ },
};

static const struct elfloader_smp_ops smp_imx6_ops = {
    .enable_method = NULL,
    .cpu_on = &smp_imx6_cpu_on,
};

static const struct elfloader_driver smp_imx6 = {
    .match_table = smp_imx6_matches,
    .type = DRIVER_SMP,
    .init = &smp_imx6_init,
    .ops = &smp_imx6_ops,
};

ELFLOADER_DRIVER(smp_imx6);
