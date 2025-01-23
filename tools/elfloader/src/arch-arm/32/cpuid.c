/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <types.h>

/* we only care about affinity bits */
#define MPIDR_MASK  (0x00ffffff)
/* read MP ID register from CPUID */
word_t read_cpuid_mpidr(void)
{
    uint32_t val;
    asm volatile("mrc p15, 0, %0, c0, c0, 5" : "=r"(val) :: "cc");
    return val & MPIDR_MASK;
}

#define CPSR_MODE_MASK          0x1f
#define CPSR_MODE_HYPERVISOR    0x1a
word_t is_hyp_mode(void)
{
    uint32_t val;
    asm volatile("mrs %0, cpsr" : "=r"(val) :: "cc");
    return ((val & CPSR_MODE_MASK) == CPSR_MODE_HYPERVISOR);
}

/* read ID register from CPUID */
uint32_t read_cpuid_id(void)
{
    uint32_t val;
    asm volatile("mrc p15, 0, %0, c0, c0, 0" : "=r"(val) :: "cc");
    return val;
}
