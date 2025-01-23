/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <kernel/gen_config.h>
#include <printf.h>
#include <types.h>
#include <cpuid.h>

#include <elfloader.h>

#define BOOTCPU 0

#define EXYNOS5_SYSRAM        0x02020000
#define EXYNOS5_POWER         0x10040000

#define EXYNOS5_SYSRAM_NS     (EXYNOS5_SYSRAM + 0x53000)
#define EXYNOS5_POWER_CPU_CFG (EXYNOS5_POWER  +  0x2000)

#define CORE_LOCAL_PWR_EN     0x3

#define SMC_SHUTDOWN          (-7)
#define SMC_DISABLE_TRUSTZONE (-1024)

/**
 * This structure and its location is defined by U-Boot
 * It controls the boot behaviour of secondary cores.
 */
typedef volatile struct {
    uint32_t bypass[2];      /* 0x00 */
    uint32_t resume_addr;    /* 0x08 */
    uint32_t resume_flag;    /* 0x0C */
    uint32_t res0[3];        /* 0x10 */
    uint32_t cpu1_boot_reg;  /* 0x1C */
    uint32_t direct_go_flag; /* 0x20 */
    uint32_t direct_go_addr; /* 0x24 */
    uint32_t cpustate[8];    /* 0x28 */ /* only 4 cpustate on 5410 */
    uint32_t clusterstate[2];   /* 0x54 */ /* missing on 5410 */
} nscode_t;

struct cso {
    uint32_t config;
    uint32_t status;
    uint32_t option;
    uint32_t res[5];
};

typedef volatile struct cpu_cfg {
    struct cso core;
    struct cso dis_irq_local;
    struct cso dis_irq_central;
    struct cso res[1];
} cpu_cfg_t;

/* U-Boot control */
nscode_t *nsscode  = (nscode_t *)EXYNOS5_SYSRAM_NS;

/* CPU configuration */
cpu_cfg_t *cpu_cfg = (cpu_cfg_t *)EXYNOS5_POWER_CPU_CFG;

extern char _start[];

void boot_cpu(int cpu, uintptr_t entry)
{
    /* Setup the CPU's entry point */
    nsscode->cpu1_boot_reg = entry;
    asm volatile("dmb");
    /* Spin up the CPU */
    cpu_cfg[cpu].core.config = CORE_LOCAL_PWR_EN;
}

void platform_init(void)
{
    if (get_cortex_a_part() == 7) {
        printf("\nSwitching CPU...\n");
        boot_cpu(BOOTCPU, (uintptr_t)_start);
        /* Shutdown */
        for (;;) {
            /*
             * Turn off interrupts before going to
             * sleep --- otherwise they could wake us up.
             */
            asm volatile(
                "msr CPSR_cxsf, #0xc" ::
            );
            smc(SMC_SHUTDOWN, 0, 0, 0);
        }
    } else {
        nsscode->cpu1_boot_reg = 0;
        smc(SMC_DISABLE_TRUSTZONE, 0, 0, 0);
    }
}
