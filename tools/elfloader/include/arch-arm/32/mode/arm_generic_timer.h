/*
 * Copyright 2021, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <cpuid.h>
#include <printf.h>

/*
 * Platforms that use the ARM generic timer in the kernel use the
 * virtual counter when not in HYP mode. The offset value does not have
 * a fixed reset value so could produce a random starting value for the
 * virtual counter at boot.
 *
 * The offset must be explicitly set to zero in the elfloader before
 * dropping to EL1 for the kernel.
 */
static inline void reset_cntvoff(void)
{
    if (is_hyp_mode()) {
        /* Set CNTVOFF_El2 to zero */
        asm volatile("mcrr p15, 4, %0, %0, c14" :: "r"(0));
    } else {
        printf("Not in hyp mode, cannot reset CNTVOFF_EL2\n");
    }
}
