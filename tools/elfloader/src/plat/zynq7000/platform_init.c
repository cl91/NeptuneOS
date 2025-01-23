/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <elfloader.h>
#include <sys_fputc.h>

#define MPCORE_PRIV               0xF8F00000

/* SCU */
#define SCU_BASE                  (MPCORE_PRIV + 0x0)
#define SCU_CTRL_OFFSET           0x000
#define SCU_FILTADDR_START_OFFSET 0x040
#define SCU_FILTADDR_END_OFFSET   0x044

#define SCU_CTRL_EN               BIT(0)
#define SCU_CTRL_ADDRFILT_EN      BIT(1)

/* SLCR */
#define SLCR_BASE                 0xF8000000
#define SLCR_LOCK_OFFSET          0x004
#define SLCR_UNLOCK_OFFSET        0x008
#define SLCR_OCM_CFG_OFFSET       0x910

#define SLCR_LOCK_KEY             0x767B
#define SLCR_UNLOCK_KEY           0xDF0D

#define SLCR_OCM_CFG_RAMHI(x)     BIT(x)
#define SLCR_OCM_CFG_RAMHI_ALL    ( SLCR_OCM_CFG_RAMHI(0) \
                                  | SLCR_OCM_CFG_RAMHI(1) \
                                  | SLCR_OCM_CFG_RAMHI(2) \
                                  | SLCR_OCM_CFG_RAMHI(3) )

#define REG(a) *(volatile uint32_t*)(a)

#define SCU(o)  REG(SCU_BASE + SCU_##o##_OFFSET)
#define SLCR(o) REG(SLCR_BASE + SLCR_##o##_OFFSET)

/* Remaps the OCM and ensures DDR is accessible at 0x00000000 */
void remap_ram(void)
{
    /*** 29.4.1 Changing Address Mapping ***/
    /* 1: Complete outstanding transactions */
    asm volatile("dsb");
    asm volatile("isb");

    /* 2-4: prime the icache with this function
     *      skipped because icache is disabled and our remapping does not
     *      affect .text section */

    /* 5-7: unlock SLCR, Modify OCM_CFG, lock SLCR */
    SLCR(UNLOCK) = SLCR_UNLOCK_KEY;
    SLCR(OCM_CFG) |= SLCR_OCM_CFG_RAMHI_ALL;
    SLCR(LOCK) = SLCR_LOCK_KEY;

    /* 8-9: Modify address filtering */
    SCU(FILTADDR_START) = 0x00000000;
    SCU(FILTADDR_END) = 0xFFE00000;

    /* 10: Enable filtering */
    SCU(CTRL) |= (SCU_CTRL_EN | SCU_CTRL_ADDRFILT_EN);

    /* Ensure completion */
    asm volatile("dmb");
}

void platform_init(void)
{
    remap_ram();
}
