/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <devices_gen.h>

#pragma once

#define dev_get_smp(dev) ((struct elfloader_smp_ops *)(dev->drv->ops))

struct elfloader_smp_ops {
    const char *enable_method;
    int (*cpu_on)(struct elfloader_device *smp_dev, struct elfloader_cpu *cpu, void *entry, void *stack);
};

struct smp_cpu_data {
    void *entry;
    void *stack;
};

extern struct smp_cpu_data secondary_data;
void secondary_startup(void);
void smp_register_handler(struct elfloader_device *dev);
int plat_cpu_on(struct elfloader_cpu *cpu, void *entry, void *stack);
