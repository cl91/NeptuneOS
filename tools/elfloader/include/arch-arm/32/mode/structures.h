/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#pragma once

#define ARM_SECTION_BITS      20
#define ARM_1GB_BLOCK_BITS    30
#define ARM_2MB_BLOCK_BITS    21

#define PDE_SIZE_BITS         2
#define PD_BITS               12
#define PD_SIZE_BITS          (PD_BITS + PDE_SIZE_BITS)

#define PTE_SIZE_BITS         2
#define PT_BITS               8
#define PT_SIZE_BITS          (PT_BITS + PTE_SIZE_BITS)

#define HYP_PGDE_SIZE_BITS    3
#define HYP_PGD_BITS          2
#define HYP_PGD_SIZE_BITS     (HYP_PGD_BITS + HYP_PGDE_SIZE_BITS)

#define HYP_PMDE_SIZE_BITS    3
#define HYP_PMD_BITS          9
#define HYP_PMD_SIZE_BITS     (HYP_PMD_BITS + HYP_PMDE_SIZE_BITS)

#define GET_PT_INDEX(x)       (((x) >> (PAGE_BITS)) & MASK(PT_BITS))

extern uint32_t _boot_pd[BIT(PD_BITS)];
extern uint32_t _boot_pt[BIT(PT_BITS)];

extern uint64_t _lpae_boot_pgd[BIT(HYP_PGD_BITS)];
extern uint64_t _lpae_boot_pmd[BIT(HYP_PGD_BITS + HYP_PMD_BITS)];

