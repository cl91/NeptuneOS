/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <kernel/gen_config.h>
#include <elfloader/gen_config.h>
#include <elfloader.h>
#include <printf.h>

/* TODO: get rid of this, make GIC initialisation part of a driver. */
#define TK1_GICD_PADDR    0x50041000
#define TK1_GICC_PADDR    0x50042000

extern void flush_dcache(void);
extern void invalidate_icache(void);

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

/* hyp call enable: 0 hvc instruction is undefined in nonsecure pl1 mode
 *                    and unpredictable in hyp mode
 *                  1 hvc is enabled in nonsecure pl1.
 */
#define SCR_HCE     (8)

/* secure instruction fetch. when in secure state, the bit disables
 * instruction fetches from non-secure memory */
#define SCR_SIF     (9)

#define MONITOR_MODE        (0x16)
#define SUPERVISOR_MODE     (0x13)
#define HYPERVISOR_MODE     (0x1a)

/* if seL4 is used a hypervior, we should enable both HCe and SCE bits.
 * the secure monitor exception handler does very limited things, so
 * we let the seL4 handle interrupts/exceptions.
 */

#define MONITOR_MODE        (0x16)
#define SUPERVISOR_MODE     (0x13)
#define HYPERVISOR_MODE     (0x1a)

void arm_halt(void)
{
    while (1) {
        asm volatile("wfe");
    }
}

/* steal the last 1 MiB physical memory for monitor mode */

#define MON_PA_START        (0x80000000 + 0x27f00000)
#define MON_PA_SIZE         (1 << 20)
#define MON_PA_END          (MON_PA_START + MON_PA_SIZE)
#define MON_PA_STACK        (MON_PA_END - 0x10)
#define MON_VECTOR_START    (MON_PA_START)
#define MON_HANDLER_START   (MON_PA_START + 0x10000)
#define LOADED_OFFSET       0x90000000

#if defined(CONFIG_ARM_MONITOR_HOOK) || defined(CONFIG_ARM_NS_SUPERVISOR_MODE) \
    || defined(CONFIG_ARM_HYPERVISOR_MODE) || defined(CONFIG_ARM_MONITOR_MODE)
static int mon_init_done = 0;

static void switch_to_mon_mode(void)
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

        /* enable hyper call */
        scr = BIT(SCR_HCE);

        asm volatile("mcr p15, 0, %0, c1, c1, 0"::"r"(scr));

        /* now switch to secure monitor mode. restoring our stack and link register in the process
         * as these two registers are banked. */
        uint32_t sp_temp = 0;
        uint32_t lr_temp = 0;
        asm volatile("mov %[SP_TEMP], sp\n"
                     "mov %[LR_TEMP], lr\n"
                     "cps %[MON_MODE]\n\t"
                     "isb\n"
                     "mov sp, %[SP_TEMP]\n"
                     "mov lr, %[LR_TEMP]\n"
                     : [SP_TEMP]"+r"(sp_temp),
                     [LR_TEMP]"+r"(lr_temp)
                     : [MON_MODE]"I"(MONITOR_MODE));
        mon_init_done = 1;
        printf("ELF loader: monitor mode init done\n");
    }
}

#endif

#ifdef CONFIG_ARM_MONITOR_HOOK

extern void arm_monitor_vector(void);
extern void arm_monitor_vector_end(void);
extern void *memcpy(void *dest, void *src, size_t n);
extern char _bootstack_top[1];

static void install_monitor_hook(void)
{
    uint32_t size = arm_monitor_vector_end - arm_monitor_vector;
    /* switch monitor mode if not already */
    switch_to_mon_mode();
    printf("Copy monitor mode vector from %x to %x size %x\n", (arm_monitor_vector), MON_VECTOR_START, size);
    memcpy((void *)MON_VECTOR_START, (void *)(arm_monitor_vector), size);

    asm volatile("mcr p15, 0, %0, c12, c0, 1"::"r"(MON_VECTOR_START));
}

#endif

#ifdef CONFIG_ARM_HYPERVISOR_MODE
static void switch_to_hyp_mode(void)
{
    uint32_t scr = 0;

    /*
     * Need to make sure anything in the write buffer is
     * in RAM, and nothing in the cache that we want to access is tagged
     * 'secure' because we're about to switch to non-secure mode.
     * Note: flush_dcache() does a flush-and-invalidate.
     */
    flush_dcache();
    invalidate_icache();

    asm volatile("mrc p15, 0, %0, c1, c1, 0":"=r"(scr));
    scr |= BIT(SCR_HCE);
    scr &= ~BIT(SCR_SCD);
    scr |= BIT(SCR_NS);
    scr &= ~BIT(SCR_SIF);
    asm volatile("mcr p15, 0, %0, c1, c1, 0"::"r"(scr));
    /* now switch to hypervisor mode. restoring our stack and link register in the process
     * as these two registers are banked. */
    uint32_t sp_temp = 0;
    uint32_t lr_temp = 0;
    asm volatile("mov %[SP_TEMP], sp\n"
                 "mov %[LR_TEMP], lr\n"
                 "cps %[HYP_MODE]\n\t"
                 "isb\n"
                 "mov sp, %[SP_TEMP]\n"
                 "mov lr, %[LR_TEMP]\n"
                 : [SP_TEMP]"+r"(sp_temp),
                 [LR_TEMP]"+r"(lr_temp)
                 : [HYP_MODE]"I"(HYPERVISOR_MODE));

    asm volatile("mrs %0, cpsr":"=r"(scr));
    printf("Load seL4 in nonsecure HYP mode %x", scr);
}
#endif

#ifdef CONFIG_ARM_NS_SUPERVISOR_MODE
static void switch_to_ns_svc_mode(void)
{
    uint32_t scr = 0;

    asm volatile("cps %0\n\t"
                 "isb\n"
                 ::"I"(SUPERVISOR_MODE));

    asm volatile("mov r0, sp");
    asm volatile("mrc p15, 0, %0, c1, c1, 0":"=r"(scr));
    scr |= BIT(SCR_NS);

    asm volatile("mcr p15, 0, %0, c1, c1, 0"::"r"(scr));
    asm volatile("mov sp, r0");

    printf("Load seL4 in nonsecure SVC mode\n");
}
#endif

extern void arm_monitor_vector(void);

#if defined(CONFIG_ARM_HYPERVISOR_MODE) || defined(CONFIG_ARM_NS_SUPERVISOR_MODE)
/* tk1 uses GIC v2 */
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

volatile struct gicd_map *gicd = (volatile struct gicd_map *)(TK1_GICD_PADDR);
volatile struct gicc_map *gicc = (volatile struct gicc_map *)(TK1_GICC_PADDR);

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
#endif

static void enable_ns_access_cp(void)
{
    uint32_t nsacr = 0;
    asm volatile("mrc p15, 0, %0, c1, c1, 2":"=r"(nsacr));

    /* enable cp10, cp11 */
    nsacr |= BIT(10) |  BIT(11);
    asm volatile("mcr p15, 0, %0, c1, c1, 2"::"r"(nsacr));

    asm volatile("isb");
}

void platform_init(void)
{
#if defined(CONFIG_ARM_MONITOR_HOOK) || defined(CONFIG_ARM_NS_SUPERVISOR_MODE) \
    || defined(CONFIG_ARM_HYPERVISOR_MODE) || defined(CONFIG_ARM_MONITOR_MODE)
    /* mon_init_done needs to explicitly initialised when booting a binary image */
    mon_init_done = 0;
#endif
#ifdef CONFIG_ARM_MONITOR_HOOK
    install_monitor_hook();
#endif

    enable_ns_access_cp();

#ifdef CONFIG_ARM_NS_SUPERVISOR_MODE
    switch_to_mon_mode();
    route_irqs_to_nonsecure();
    switch_to_ns_svc_mode();
#endif

#ifdef CONFIG_ARM_HYPERVISOR_MODE
    switch_to_mon_mode();
    route_irqs_to_nonsecure();
    switch_to_hyp_mode();
#endif

#ifdef CONFIG_ARM_MONITOR_MODE
    switch_to_mon_mode();
#endif

}
