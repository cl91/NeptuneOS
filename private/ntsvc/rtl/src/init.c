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
/*
 * Constructor and destructor handling.
 */

typedef void (*routine)(void);

/*
 * Constructors
 */
void _init(void);
extern routine __preinit_array_start[];
extern routine __preinit_array_end[];
extern routine __init_array_start[];
extern routine __init_array_end[];

/*
 * Destructors
 */
void _fini(void);
extern routine __fini_array_start[];
extern routine __fini_array_end[];

void __sel4runtime_run_constructors(void) {
    int preinit_array_len
        = &__preinit_array_end[0]
        - &__preinit_array_start[0];
    for (int f = 0; f < preinit_array_len; f++) {
        __preinit_array_start[f]();
    }
    _init();
    int init_array_len
        = &__init_array_end[0]
        - &__init_array_start[0];
    for (int f = 0; f < init_array_len; f++) {
        __init_array_start[f]();
    }
}

void __sel4runtime_run_destructors(void) {
    int fini_array_len
        = &__fini_array_end[0]
        - &__fini_array_start[0];
    for (int f = fini_array_len - 1; f >= 0; f--) {
        __fini_array_start[f]();
    }
    _fini();
}
