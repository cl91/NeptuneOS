/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <kernel/gen_config.h>
#include <elfloader/gen_config.h>
#include <types.h>
#include <elfloader.h>
#include <mode/structures.h>
#include <printf.h>
#include <abort.h>

/*
* Create a "boot" page table, which contains a 1:1 mapping below
* the kernel's first vaddr, and a virtual-to-physical mapping above the
* kernel's first vaddr.
*/
void init_boot_vspace(struct image_info *kernel_info)
{
    word_t i;

    vaddr_t first_vaddr = kernel_info->virt_region_start;
    vaddr_t last_vaddr = kernel_info->virt_region_end;
    paddr_t first_paddr = kernel_info->phys_region_start;

    _boot_pgd_down[0] = ((uintptr_t)_boot_pud_down) | BIT(1) | BIT(0); /* its a page table */

    for (i = 0; i < BIT(PUD_BITS); i++) {
        _boot_pud_down[i] = (i << ARM_1GB_BLOCK_BITS)
                            | BIT(10) /* access flag */
                            | (0 << 2) /* strongly ordered memory */
                            | BIT(0); /* 1G block */
    }

    _boot_pgd_up[GET_PGD_INDEX(first_vaddr)]
        = ((uintptr_t)_boot_pud_up) | BIT(1) | BIT(0); /* its a page table */

    _boot_pud_up[GET_PUD_INDEX(first_vaddr)]
        = ((uintptr_t)_boot_pmd_up) | BIT(1) | BIT(0); /* its a page table */

    /* We only map in 1 GiB, so check that the kernel doesn't cross 1GiB boundary. */
    if ((first_vaddr & ~MASK(ARM_1GB_BLOCK_BITS)) != (last_vaddr & ~MASK(ARM_1GB_BLOCK_BITS))) {
        printf("We only map 1GiB, but kernel vaddr range covers multiple GiB.\n");
        abort();
    }
    for (i = GET_PMD_INDEX(first_vaddr); i < BIT(PMD_BITS); i++) {
        _boot_pmd_up[i] = first_paddr
                          | BIT(10) /* access flag */
#if CONFIG_MAX_NUM_NODES > 1
                          | (3 << 8) /* make sure the shareability is the same as the kernel's */
#endif
                          | (4 << 2) /* MT_NORMAL memory */
                          | BIT(0); /* 2M block */
        first_paddr += BIT(ARM_2MB_BLOCK_BITS);
    }
}

void init_hyp_boot_vspace(struct image_info *kernel_info)
{
    word_t i;
    word_t pmd_index;
    vaddr_t first_vaddr = kernel_info->virt_region_start;
    paddr_t first_paddr = kernel_info->phys_region_start;
    _boot_pgd_down[0] = ((uintptr_t)_boot_pud_down) | BIT(1) | BIT(0);

    for (i = 0; i < BIT(PUD_BITS); i++) {
        _boot_pud_down[i] = (i << ARM_1GB_BLOCK_BITS)
                            | BIT(10) /* access flag */
                            | (0 << 2) /* strongly ordered memory */
                            | BIT(0); /* 1G block */
    }

    _boot_pgd_down[GET_PGD_INDEX(first_vaddr)]
        = ((uintptr_t)_boot_pud_up) | BIT(1) | BIT(0); /* its a page table */

    _boot_pud_up[GET_PUD_INDEX(first_vaddr)]
        = ((uintptr_t)_boot_pmd_up) | BIT(1) | BIT(0); /* its a page table */

    pmd_index = GET_PMD_INDEX(first_vaddr);
    for (i = pmd_index; i < BIT(PMD_BITS); i++) {
        _boot_pmd_up[i] = (((i - pmd_index) << ARM_2MB_BLOCK_BITS) + first_paddr)
                          | BIT(10) /* access flag */
#if CONFIG_MAX_NUM_NODES > 1
                          | (3 << 8)
#endif
                          | (4 << 2) /* MT_NORMAL memory */
                          | BIT(0); /* 2M block */
    }
}
