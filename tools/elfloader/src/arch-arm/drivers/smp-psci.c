/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <elfloader_common.h>
#include <devices_gen.h>
#include <drivers/common.h>
#include <drivers/smp.h>
#include <armv/machine.h>
#include <psci.h>
#include <armv/smp.h>

#include <printf.h>
#include <types.h>

static int smp_psci_cpu_on(UNUSED struct elfloader_device *dev,
                           UNUSED struct elfloader_cpu *cpu, UNUSED void *entry, UNUSED void *stack)
{
#if CONFIG_MAX_NUM_NODES > 1
    if (cpu->extra_data == PSCI_METHOD_HVC) {
        printf("HVC is not supported for PSCI!\n");
        return -1;
    }
    secondary_data.entry = entry;
    secondary_data.stack = stack;
    dmb();
    int ret = psci_cpu_on(cpu->cpu_id, (unsigned long)&secondary_startup, 0);
    if (ret != PSCI_SUCCESS) {
        printf("Failed to bring up core 0x%x with error %d\n", cpu->cpu_id, ret);
        return -1;
    }

    return 0;
#else
    return -1;
#endif
}

static int smp_psci_init(struct elfloader_device *dev,
                         UNUSED void *match_data)
{
    smp_register_handler(dev);
    return 0;
}


static const struct dtb_match_table smp_psci_matches[] = {
    { .compatible = "arm,psci-0.2" },
    { .compatible = "arm,psci-1.0" },
    { .compatible = NULL /* sentinel */ },
};

static const struct elfloader_smp_ops smp_psci_ops = {
    .enable_method = "psci",
    .cpu_on = &smp_psci_cpu_on,
};

static const struct elfloader_driver smp_psci = {
    .match_table = smp_psci_matches,
    .type = DRIVER_SMP,
    .init = &smp_psci_init,
    .ops = &smp_psci_ops,
};

ELFLOADER_DRIVER(smp_psci);
