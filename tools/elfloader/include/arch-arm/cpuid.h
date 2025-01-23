/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#pragma once

#include <types.h>

/* read ID register from CPUID */
uint32_t read_cpuid_id(void);

/* read MP ID register from CPUID */
uint32_t read_cpuid_mpidr(void);

/* check if CPU is in HYP/EL2 mode */
word_t is_hyp_mode(void);

/* Pretty print CPUID information */
void print_cpuid(void);

/* Returns the Cortex-Ax part number, or -1 */
int get_cortex_a_part(void);

