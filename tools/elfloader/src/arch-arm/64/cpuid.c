/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <armv/machine.h>
#include <types.h>

/* we only care about the affinity bits */
#define MPIDR_MASK (0xff00ffffff)

word_t read_cpuid_mpidr(void)
{
    uint64_t val;
    asm volatile("mrs %x0, mpidr_el1" : "=r"(val) :: "cc");
    return val & MPIDR_MASK;
}

#define CURRENTEL_EL2           (2 << 2)
word_t is_hyp_mode(void)
{
    uint32_t val;
    asm volatile("mrs %x0, CurrentEL" : "=r"(val) :: "cc");
    return (val == CURRENTEL_EL2);
}

uint32_t read_cpuid_id(void)
{
    uint32_t val;
    asm volatile("mrs %x0, midr_el1" : "=r"(val) :: "cc");
    return val;
}
