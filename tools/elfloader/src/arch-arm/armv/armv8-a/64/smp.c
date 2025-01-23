/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <kernel/gen_config.h>
#include <elfloader/gen_config.h>

#if CONFIG_MAX_NUM_NODES > 1
#include <types.h>
#include <elfloader.h>
#include <armv/machine.h>
#include <armv/smp.h>
#include <printf.h>

unsigned long core_stacks[CONFIG_MAX_NUM_NODES][STACK_SIZE / sizeof(unsigned long)] ALIGN(BIT(12));
volatile int core_up[CONFIG_MAX_NUM_NODES];

extern void core_entry_head(void);
extern void non_boot_main(void);

void core_entry(uint64_t sp)
{
    int id;
    // get the logic ID
    id = (sp - (unsigned long)&core_stacks[0][0]) / STACK_SIZE;
    // save the ID and pass it to the kernel
    MSR("tpidr_el1", id);

    core_up[id] = id;
    dmb();
    non_boot_main();
}

int is_core_up(int i)
{
    return core_up[i] == i;
}

#endif
