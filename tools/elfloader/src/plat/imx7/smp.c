/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright: Linux Kernel team
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * The code in here is derived from the Linux kernel
 */

#include <kernel/gen_config.h>
#include <elfloader/gen_config.h>

#include <printf.h>
#include <armv/machine.h>
#include <scu.h>
#include <abort.h>

#if CONFIG_MAX_NUM_NODES > 1
VISIBLE volatile word_t smp_aps_index = 1;

/* System Reset Controller base address */
#define SRC_BASE 0x30390000
#define GPC_BASE 0x303a0000

#define SRC_SCR             0x000
#define SRC_GPR1            0x020
#define BP_SRC_SCR_WARM_RESET_ENABLE    0
#define BP_SRC_SCR_CORE1_RST        14
#define BP_SRC_SCR_CORE1_ENABLE     22

#define GPC_CPU_PGC_SW_PUP_REQ              0xf0
#define BM_CPU_PGC_SW_PDN_PUP_REQ_CORE1_A7  0x2
#define GPC_PGC_C1                          0x840
#define BP_SRC_A7RCR1_A7_CORE1_ENABLE       1

#define SRC_A7RCR1  0x008
#define SRC_GPR1_V2 0x074

#define REG(base,offset) (*(volatile unsigned int*)(((void *)(base))+(offset)))

void imx_non_boot(void);

static void src_init(void)
{
    unsigned int val;
    val = REG(SRC_BASE, SRC_SCR);
    val &= ~(1 << BP_SRC_SCR_WARM_RESET_ENABLE);
    REG(SRC_BASE, SRC_SCR) = val;
}

static void gpc_core1_up(void)
{
    unsigned int val = REG(GPC_BASE, GPC_CPU_PGC_SW_PUP_REQ);

    REG(GPC_BASE, GPC_PGC_C1) = 1;

    val |= BM_CPU_PGC_SW_PDN_PUP_REQ_CORE1_A7;

    REG(GPC_BASE, GPC_CPU_PGC_SW_PUP_REQ) = val;

    while ((REG(GPC_BASE, GPC_CPU_PGC_SW_PUP_REQ) & BM_CPU_PGC_SW_PDN_PUP_REQ_CORE1_A7) != 0);

    REG(GPC_BASE, GPC_PGC_C1) = 0;
}

static void src_enable_cpu(int cpu)
{
    unsigned int mask, val;

    gpc_core1_up();
    mask = 1 << (BP_SRC_A7RCR1_A7_CORE1_ENABLE + cpu - 1);
    val = REG(SRC_BASE, SRC_A7RCR1);
    val |= mask;
    REG(SRC_BASE, SRC_A7RCR1) = val;
}

static void src_set_cpu_jump(int cpu, unsigned int jump_addr)
{
    REG(SRC_BASE, SRC_GPR1_V2 + cpu * 8) = (unsigned int)jump_addr;
    dsb();
}

void init_cpus(void)
{
    unsigned int i, num;

    src_init();

    /* get core count from L2CTLR */
    asm volatile("mrc p15, 1, %0, c9, c0, 2": "=r"(num));
    num = ((num >> 24) & 0x3) + 1;

    if (num > CONFIG_MAX_NUM_NODES) {
        num = CONFIG_MAX_NUM_NODES;
    } else if (num < CONFIG_MAX_NUM_NODES) {
        printf("Error: Unsupported number of CPUs! This platform has %u CPUs, while static configuration provided is %u CPUs\n",
               num, CONFIG_MAX_NUM_NODES);
        abort();
    }

    printf("Bringing up %d other cpus\n", num - 1);
    for (i = 1; i < num; i++) {
        src_set_cpu_jump(i, (unsigned int)imx_non_boot);
        src_enable_cpu(i);
    }
}
#endif /* CONFIG_MAX_NUM_NODES */
