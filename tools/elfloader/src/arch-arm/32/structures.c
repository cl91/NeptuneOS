/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <elfloader.h>
#include <types.h>
#include <mode/structures.h>

/* Page directory for Stage1 translation in PL1 (short-desc format)*/
uint32_t _boot_pd[BIT(PD_BITS)] ALIGN(BIT(PD_SIZE_BITS));
uint32_t _boot_pt[BIT(PT_BITS)] ALIGN(BIT(PT_SIZE_BITS));

/* Page global and middle directory for Stage1 in HYP mode (long-desc format) */
uint64_t _lpae_boot_pgd[BIT(HYP_PGD_BITS)] ALIGN(BIT(HYP_PGD_SIZE_BITS));
uint64_t _lpae_boot_pmd[BIT(HYP_PGD_BITS + HYP_PMD_BITS)] ALIGN(BIT(HYP_PMD_SIZE_BITS));

/*
 * These are helper functions which let the ASM work when we're relocated,
 * and save the ASM from manually having to figure out offsets to access these.
 */
void *get_boot_pd(void)
{
    return _boot_pd;
}

void *get_lpae_boot_pgd(void)
{
    return _lpae_boot_pgd;
}
