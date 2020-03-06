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
 * The seL4 run-time interface.
 *
 * This provides an interface to the values managed by sel4runtime.
 */
#include <stddef.h>
#include <stdint.h>
#include <sel4/sel4.h>
#include <thread.h>

#pragma once

/*
 * Get the name of the process.
 *
 * Returns the basename of the first argument in argv.
 */
char const *sel4runtime_process_name(void);

/*
 * Get the address of the TLS base register.
 */
static inline uintptr_t sel4runtime_get_tls_base(void);

/*
 * Set the address of the TLS base register.
 */
static inline void sel4runtime_set_tls_base(uintptr_t tls_base);

/*
 * Get the bootinfo pointer if the process was provided a bootinfo
 * cspace descriptor.
 */
seL4_BootInfo *sel4runtime_bootinfo(void);

/*
 * Get the size in bytes needed to store the thread's TLS.
 */
size_t sel4runtime_get_tls_size(void);

/*
 * Get the offset used to calculate the thread pointer from the
 * starting address of the thread area.
 */
size_t sel4runtime_get_tp_offset(void);

/*
 * Check if the TLS for the initial thread is enabled.
 *
 * If the TLS for the initial thread was too large to fit inside the
 * static region of the runtime, this will return false and
 * sel4runtime_move_initial_tls should be used to initialise it into a
 * new location.
 */
int sel4runtime_initial_tls_enabled(void);

/*
 * Write the TLS image for a new thread into the provided memory image.
 * The TLS for the initial thread must be enabled before this is called.
 *
 * @returns the pointer to the TLS that should be used to call
 *          seL4_TCB_SetTLSBase or NULL on error.
 */
uintptr_t sel4runtime_write_tls_image(void *tls_memory);

/*
 * Move the TLS for the current thread into a new memory location.
 *
 * Particularly useful for enabling TLS in the initial process where the
 * TLS image exeeded the size of the static TLS region in the runtime.
 *
 * WARNING: This will not prevent re-initialisation of the TLS for the
 * initial thread (even by other threads). This should only be used at
 * the start of a process only if `sel4utils_initial_tls_enabled`
 * returns false.
 *
 * @returns the pointer to the TLS that should be used to call
 *          seL4_TCB_SetTLSBase.
 */
uintptr_t sel4runtime_move_initial_tls(void *tls_memory);

/*
 * Writes into a thread_local variable of another thread.
 *
 * This assumes that TLS has been initialised for the current thread.
 */
#define sel4runtime_set_tls_variable(thread_pointer, variable, value) ({\
    _Static_assert(\
        sizeof(variable) == sizeof(value), \
        "Set value of same size" \
    ); \
    typeof (variable) typed_value = value; \
    __sel4runtime_write_tls_variable( \
        thread_pointer, \
        (unsigned char *)&(variable), \
        (unsigned char *)&(typed_value), \
        sizeof(typed_value) \
    ); \
})

/*
 * Copies data into the equivalent address in the TLS of another thread.
 *
 * This assumes that TLS has been initialised for the current thread.
 */
int __sel4runtime_write_tls_variable(
    uintptr_t dest_tls_base,
    unsigned char *local_tls_dest,
    unsigned char *src,
    size_t bytes
);
