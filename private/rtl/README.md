<!--
     Copyright 2019, Data61
     Commonwealth Scientific and Industrial Research Organisation (CSIRO)
     ABN 41 687 119 230.

     This software may be distributed and modified according to the terms of
     the BSD 2-Clause license. Note that NO WARRANTY is provided.
     See "LICENSE_BSD2.txt" for details.

     @TAG(DATA61_BSD)
-->
# The seL4 Run-time

This provides a minimal runtime for running a C or C-compatible process, 
i.e. one with a C-like `main`, in a minimal seL4 environment.

This runtime provides mechanisms for accessing everything a standard
process would expect to need at start and provides additional utilities
for delegating the creation of processes and threads.

## Standard Processes

All processes (except for the root task) will use the entry-points
provided here as normal and require the `_start` entry-point provided in
the architecture-dependant `crt0.S`. This will then bootstrap into the
runtime entry-point `__sel4_start_c` which simply processes the stack to
find the argument, environment, and auxiliary vectors.

The found vectors, along with`main`, are passed into
`__sel4_start_main` which configures the runtime before starting
`main`.

## Root Task

The root task requires an alternate entry-point `_sel4_start` which
assumes that the `seL4_BootInfo` argument has been passed to it and that
it has not been given a stack.

This entry-point moves onto a static 16 kilobyte stack before invoking
`__sel4_start_root`, which constructs the argument, environment, and
auxiliary vectors. It then passes the constructed vectors, along with
`main`, into `__sel4_start_main` which configures the runtime before
starting `main`.

## Thread-local storage layout

There are two standard layouts for thread local storage commonly used.
One where the TLS base address refers to the first address in memory of
the region and one where it refers to the address that immediately
follows the region. Intel's x86_64 and ia32 architectures use the latter
method as it aligns with the segmentation view of memory presented by
the processor. Most other platforms use former method, where the TLS can
be said to be 'above' the thread pointer.

In order to store metadata for the current thread in the same memory
allocation as the TLS, the run-time utilises memory on the other side of
the thread pointer for it's thread structure.
