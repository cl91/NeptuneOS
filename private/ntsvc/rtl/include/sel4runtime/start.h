/*
 * Copyright 2019, Data61
 * Commonwealth Scientific and Industrial Research Organisation (CSIRO)
 * ABN 41 687 119 230.
 *
 * This software may be distributed and modified according to the terms of
 * the BSD 2-Clause license. Note that NO WARRANTY is provided.
 * See "LICENSE_BSD2.txt" for details.
 *
 * @TAG(DATA61_BSD)
 */
#pragma once

#define NULL (0)
#define ARRAY_LENGTH(a) (sizeof(a) / sizeof(a[0]))

// Entry into C program.
int main();

/*
 * The this triggers the environment to be set up for the runtime before
 * the environment is loaded.
 */
void __sel4runtime_start_main(
    int (*main)(),
    unsigned long argc,
    char const * const *argv,
    char const * const *envp
);
