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
#include <sel4/sel4.h>
#include <sel4runtime.h>

void __sel4runtime_start_main(
    int (*main)(),
    unsigned long argc,
    char const * const *argv,
    char const * const *envp
) {
    main(argc, argv, envp);
}
