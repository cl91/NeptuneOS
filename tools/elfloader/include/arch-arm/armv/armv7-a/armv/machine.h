/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#pragma once

static inline void wfi(void)
{
    asm volatile("wfi" ::: "memory");
}

static inline void dsb(void)
{
    asm volatile("dsb" ::: "memory");
}

static inline void dmb(void)
{
    asm volatile("dmb" ::: "memory");
}

static inline void isb(void)
{
    asm volatile("isb" ::: "memory");
}

