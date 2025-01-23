/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2020, HENSOLDT Cyber GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <kernel/gen_config.h>
#include <elfloader/gen_config.h>
#include <elfloader.h>
#include <printf.h>

#define IMX6_SCU_PADDR          0x00a00000
#define IMX6_SCU_SACR_PADDR     (IMX6_SCU_PADDR + 0x50)
#define IMX6_SCU_NSACR_PADDR    (IMX6_SCU_PADDR + 0x54)
#define IMX6_CSU_PADDR          0x021c0000
#define IMX6_CSU_SIZE           160
#define IMX6_GICD_PADDR         0x00a01000
#define IMX6_GICC_PADDR         0x00a00100

/* non-secure bit: 0 secure; 1 nonsecure */
#define SCR_NS      (0)

/* controls which mode takes IRQ exceptions: 0 IRQ mode; 1 monitor mode */
#define SCR_IRQ     (1)

/* FIQ mode control */
#define SCR_FIQ     (2)

/* external abort handler. 0 abort mode; 1 monitor mode */
#define SCR_EA      (3)

/* CPSR.F can be modified in nonsecure mode */
#define SCR_FW      (4)

/* CPSR.A can be modified in nonsecure mode */
#define SCR_AW      (5)

/* not early terminination. not implmented */
#define SCR_NET     (6)

/* secure monitor call disabled: 0 smc executes in nonsecure state;
 * 1 undefined instruction in nonsecure state
 */
#define SCR_SCD     (7)

/* secure instruction fetch. when in secure state, the bit disables
 * instruction fetches from non-secure memory */
#define SCR_SIF     (9)

#define MONITOR_MODE        (0x16)
#define SUPERVISOR_MODE     (0x13)

static int mon_init_done = 0;

void arm_halt(void)
{
    while (1) {
        asm volatile("wfe");
    }
}

void check_mode(void)
{
    uint32_t cpsr = 0;
    asm volatile("mrs %0, cpsr":"=r"(cpsr));
    printf("CPSR is %x\n", cpsr);
}

asm(".arch_extension sec\n");

#ifndef CONFIG_ARM_S_SUPERVISOR_MODE
UNUSED static void switch_to_mon_mode(void)
{
    if (mon_init_done == 0) {
        /* first need to make sure that we are in secure world */
        uint32_t scr = 0;
        /* read the secure configuration register, note if we are
         * in nonsecure world, the instruction fails.
         */

        asm volatile("mrc p15, 0, %0, c1, c1, 0":"=r"(scr));

        if (scr & BIT(SCR_NS)) {
            printf("In nonsecure world, you should never see this!\n");
            arm_halt();
        }

        check_mode();

        /* now switch to secure monitor mode */
        asm volatile("mov r8, sp\n\t"
                     "cps %0\n\t"
                     "isb\n"
                     "mov sp, r8\n\t"
                     ::"I"(MONITOR_MODE));
        mon_init_done = 1;
        check_mode();
        printf("ELF loader: monitor mode init done\n");
    }
}
#endif

#ifdef CONFIG_ARM_MONITOR_HOOK

#error please ensure the MON_VECTOR_START is not used by the kernel.

/* The physical address region [MON_VECTOR_START, MON_VECTOR_START + size)
 * must not be used by the seL4 kernel. The VECTOR_BASE must be
 * the same as MON_VECTOR_START */
#if defined(CONFIG_PLAT_IMX6DQ)
#define MON_VECTOR_START    (0x10000000)
#elif defined(CONFIG_PLAT_IMX6SX)
#define MON_VECTOR_START    (0x80000000)
#else
#error "unknown i.MX6 SOC"
#endif
extern void arm_monitor_vector(void);
extern void arm_monitor_vector_end(void);
extern void *memcpy(void *dest, void *src, size_t n);

static void install_monitor_hook(void)
{
    uint32_t size = arm_monitor_vector_end - arm_monitor_vector;
    switch_to_mon_mode();
    printf("Copy monitor mode vector from %x to %x size %x\n", (arm_monitor_vector), MON_VECTOR_START, size);
    memcpy((void *)MON_VECTOR_START, (void *)(arm_monitor_vector), size);
    asm volatile("dmb\n isb\n");
    asm volatile("mcr p15, 0, %0, c12, c0, 1"::"r"(MON_VECTOR_START));
}
#endif /* end of CONFIG_ARM_MONITOR_HOOK */

#ifdef CONFIG_ARM_NS_SUPERVISOR_MODE
static void enable_ns_access_cp(void)
{
    uint32_t nsacr = 0;
    asm volatile("mrc p15, 0, %0, c1, c1, 2":"=r"(nsacr));

    /* enable cp10, cp11, TL, and PLE access */
    nsacr |= BIT(10) |  BIT(11) | BIT(17) | BIT(16);
    asm volatile("mcr p15, 0, %0, c1, c1, 2"::"r"(nsacr));
}

struct gicd_map {
    uint32_t enable;
    uint32_t ic_type;
    uint32_t dist_ident;
    uint32_t res1[29];
    uint32_t security[32];
    uint32_t enable_set[32];
    uint32_t enable_clr[32];
    uint32_t pending_set[32];
    uint32_t pending_clr[32];
    uint32_t active[32];
    uint32_t res2[32];
    uint32_t priority[255];
};

struct gicc_map {
    uint32_t ctrl;
    uint32_t pri_mask;
    uint32_t pb_c;
    uint32_t int_ack;
    uint32_t eoi;
};

volatile struct gicd_map *gicd = (volatile struct gicd_map *)(IMX6_GICD_PADDR);
volatile struct gicc_map *gicc = (volatile struct gicc_map *)(IMX6_GICC_PADDR);

static void route_irqs_to_nonsecure(void)
{
    int i = 0;
    int nirqs = 32 * ((gicd->ic_type & 0x1f) + 1);
    printf("Number of IRQs: %d\n", nirqs);
    gicd->enable = 0;

    /* note: the security and priority initialisations in
     * non-secure mode will not work, but use the values
     * set by secure mode.
     */

    /* set all irqs to group 1 - nonsecure */
    for (i = 0; i < nirqs; i += 32) {
        gicd->security[i >> 5] = 0xffffffff;
    }

    /* assign the irqs in a single priority group: no preemptions */
    for (i = 0; i < nirqs; i += 4) {
        gicd->priority[i >> 2] = 0x80808080;
    }

    gicc->ctrl = 0;

    /* writing 255 always set the largest (lowest) priority value.
     * missing this hurts health */
    gicc->pri_mask = 0xff;
}

/* enable nonsecure access of the I/O devices */
static void set_csu(void)
{
    volatile uint32_t *addr = (volatile uint32_t *)IMX6_CSU_PADDR;
    uint32_t size = 0;

    while (size < IMX6_CSU_SIZE / sizeof(uint32_t)) {
        *addr = 0x00ff00ff;
        asm volatile("dsb");
        addr++;
        size++;
    }

    /* please check the rest of CSU registers if some
     * devices do not work. See the Security Reference
     * Manual for i.MX6. */
}

static void set_smp_bit(void)
{
    uint32_t acr = 0;
    uint32_t nsacr = 0;
    asm volatile("mrc p15, 0, %0, c1, c0, 1":"=r"(acr));
    acr |= BIT(6);
    asm volatile("mcr p15, 0, %0, c1, c0, 1"::"r"(acr));

    /* allow nonsecure to change smp bit */
    asm volatile("mrc p15, 0, %0, c1, c1, 2":"=r"(nsacr));
    nsacr |= BIT(18);
    asm volatile("mcr p15, 0, %0, c1, c1, 2"::"r"(nsacr));

}

/* give access to the SCU registers for all cores in nonsecure world */
static void enable_scu_ns_access(void)
{
    *((volatile uint32_t *)(IMX6_SCU_SACR_PADDR)) = 0xf;
    *((volatile uint32_t *)(IMX6_SCU_NSACR_PADDR)) = 0x1fff;

}
#endif /* end of CONFIG_ARM_NS_SUPERVISOR_MODE */

/* the elfloader put us in secure svc mode */
void platform_init(void)
{
    mon_init_done = 0;

#ifdef CONFIG_ARM_MONITOR_HOOK
    install_monitor_hook();
#endif

#ifdef CONFIG_ARM_NS_SUPERVISOR_MODE
    /* if the image is binary, the mon_init_done is not properly initialised */
    switch_to_mon_mode();
    enable_scu_ns_access();
    enable_ns_access_cp();
    set_smp_bit();
    set_csu();
    route_irqs_to_nonsecure();
    /* ignore the name, we switch to nonsecure supervisor mode */
    asm volatile("push {r0, r1}              \n\t"
                 "mov  r0, sp                \n\t"
                 "mov  r1, #1                \n\t"
                 "mcr  p15, 0, r1, c1, c1, 0 \n\t"
                 "isb                        \n\t"
                 "ldr  r1, =0x1d3            \n\t"
                 "msr  spsr_cxfs, r1         \n\t"
                 "ldr  lr, =mode_switch      \n\t"
                 "movs pc, lr                \n\t"
                 "mode_switch:               \n\t"
                 "isb                        \n\t"
                 "mov  sp, r0                \n\t"
                 "pop  {r0, r1}              \n\t"
                );

    return;
#endif
#ifdef CONFIG_ARM_MONITOR_MODE
    switch_to_mon_mode();
#endif
}
