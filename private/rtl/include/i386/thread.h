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
#include <autoconf.h>
#include <stdint.h>

/*
 * Obtain the value of the TLS base for the current thread.
 */
static inline uintptr_t sel4runtime_get_tls_base(void)
{
    uintptr_t tp;
    __asm__ __volatile__("movl %%gs:0,%0" : "=r"(tp));
    return tp;
}

#ifdef CONFIG_SET_TLS_BASE_SELF
/*
 * Set the value of the TLS base for the current thread.
 */
static inline void sel4runtime_set_tls_base(uintptr_t tls_base)
{
    seL4_SetTLSBase(tls_base);
}
#else
#error "Set TLS for ia32 not implemented"
#endif /* CONFIG_SET_TLS_BASE_SELF */
