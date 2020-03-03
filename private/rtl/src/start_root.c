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
#include <start.h>

/*
 * As this file is only included when we are running a root server,
 * these symbols must exist and be provided for this file to function
 * properly.
 *
 * This will generate a link time error if this function is used outside
 * of a root server.
 */

extern unsigned int _tdata_start[];
extern unsigned int _tdata_end[];
extern unsigned int _tbss_end[];

/*
 * The entrypoint into a root task is somewhat different to the
 * entrypoint into a regular process. The kernel does not provide a
 * stack to the root task nor does it conform to System-V ABI; instead
 * it simply starts execution at the entrypoint with the first argument
 * being the pointer to the seL4_BootInfo.
 *
 * This is invoked by _sel4_start, which simply sets up a static stack
 * and passes the argument to us.
 */
void __sel4_start_root(seL4_BootInfo *boot_info) {

    char const * const envp[] = {
        "seL4=1",
        NULL,
    };

    char const * const argv[] = {
        "rootserver",
        NULL,
    };

    __sel4runtime_start_main(main, ARRAY_LENGTH(argv), argv, envp);
}
