/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <abort.h>
#include <types.h>
#include <printf.h>

#define print_register(_r) do{                              \
        uint64_t val;                                       \
        asm volatile("mrs %0," #_r : "=r"(val));            \
        printf(#_r": %lx\n", val);                          \
    }while(0)

void invalid_vector_entry(void)
{
    printf("ELF-LOADER: Invalid exception received!\n");
    abort();
}

void el1_sync(void)
{
    printf("ELF-LOADER: Synchronous exception received:\n");
    print_register(esr_el1);
    print_register(elr_el1);
    print_register(spsr_el1);
    print_register(far_el1);
    abort();
}
