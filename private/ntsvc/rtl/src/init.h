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
 *
 * Constructors and destructors allow for running code before `main` and
 * during `exit` respectively.
 */

/*
 * Executes the functions described in the preinit_array, _init, and
 * init_array.
 */
void __sel4runtime_run_constructors(void);

/*
 * Executes the functions described in the fini_array and _fini.
 */
void __sel4runtime_run_destructors(void);
