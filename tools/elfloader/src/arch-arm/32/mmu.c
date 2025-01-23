/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <types.h>
#include <elfloader.h>
#include <mode/structures.h>

#define ARM_VECTOR_TABLE    0xffff0000
extern char arm_vector_table[1];
/*
 * Create a "boot" page directory, which contains a 1:1 mapping below
 * the kernel's first vaddr, and a virtual-to-physical mapping above the
 * kernel's first vaddr.
 */
void init_boot_vspace(struct image_info *kernel_info)
{
    uint32_t i;
    vaddr_t first_vaddr = kernel_info->virt_region_start;
    paddr_t first_paddr = kernel_info->phys_region_start;

    /* identity mapping below kernel window */
    for (i = 0; i < (first_vaddr >> ARM_SECTION_BITS); i++) {
        _boot_pd[i] = (i << ARM_SECTION_BITS)
                      | BIT(10) /* kernel-only access */
                      | BIT(1); /* 1M section */
    }

    /* mapping of kernel window, except last 1M*/
    for (i = 0; i < ((-first_vaddr) >> ARM_SECTION_BITS) - 1; i++) {
        _boot_pd[i + (first_vaddr >> ARM_SECTION_BITS)]
            = ((i << ARM_SECTION_BITS) + first_paddr)
              | BIT(10) /* kernel-only access */
              | BIT(1); /* 1M section */
    }

    /* map page table covering last 1M of virtual address space to page directory */
    _boot_pd[i + (first_vaddr >> ARM_SECTION_BITS)]
        = ((uintptr_t)_boot_pt)
          | BIT(9)
          | BIT(0); /* page table */

    /* map vector table */
    _boot_pt[GET_PT_INDEX(ARM_VECTOR_TABLE)]
        = ((uintptr_t)arm_vector_table)
          | BIT(4)  /* kernel-only access */
          | BIT(1); /* 4K page */
}

/**
 * Performs the same operation as init_boot_pd, but initialises
 * the LPAE page table. In this case, 3 L2 tables are concatenated.
 * PGD entries point to the appropriate L2 table.
 */
void init_hyp_boot_vspace(struct image_info *kernel_info)
{
    uint32_t i, k;
    vaddr_t first_vaddr = kernel_info->virt_region_start;
    paddr_t first_paddr = kernel_info->phys_region_start;

    /* Map in L2 page tables */
    for (i = 0; i < 4; i++) {
        _lpae_boot_pgd[i] = ((uintptr_t)_lpae_boot_pmd + (i << PAGE_BITS))
                            | BIT(1)  /* Page table */
                            | BIT(0); /* Valid */
    }
    /* identity mapping below kernel window */
    for (i = 0; i < (first_vaddr >> ARM_2MB_BLOCK_BITS); i++) {
        _lpae_boot_pmd[i] = (i << ARM_2MB_BLOCK_BITS)
                            | BIT(10) /* AF - Not always HW managed */
                            | BIT(0); /* Valid */
    }
    /* mapping of kernel window */
    for (k = 0; k < ((-first_vaddr) >> ARM_2MB_BLOCK_BITS); k++) {
        _lpae_boot_pmd[i + k] = ((k << ARM_2MB_BLOCK_BITS) + first_paddr)
                                | BIT(10) /* AF - Not always HW managed */
                                | BIT(0); /* Valid */
    }
}
