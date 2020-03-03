<!--
     Copyright 2019, Data61
     Commonwealth Scientific and Industrial Research Organisation (CSIRO)
     ABN 41 687 119 230.

     This software may be distributed and modified according to the terms of
     the BSD 2-Clause license. Note that NO WARRANTY is provided.
     See "LICENSE_BSD2.txt" for details.

     @TAG(DATA61_BSD)
-->
# C Run-time

The standard convention for a static C run-time provides the following 3
files:

* `crt0.o`; This provides the `_start` symbol which is used as the entry
  point into a C program.
* `crti.o`; This provides the prologue to the `_init` and `_fini`
  symbols. As it occurs in the linker arguments _before_ other object
  files, other object files may add function calls to the body of these
  symbols.
* `crtn.o`; This provides the epilogue to the `_init` and `_fini`
  symbols and occurs in the linker arguments after all other object
  files.

## Constructors and Destructors.

The C runtime provides a mechanism for providing functions to be
executed before and after `main` as constructors and destructors for
object files and global state.

There are two mechanisms that provide this as documented in the [System
V ABI][system-v-abi].

The first is the aforementioned `_init` and `_fini` symbols. The second
is a set of regions called `.preinit_array`, `.init_array`, and
`.fini_array`. Each of these is simply a vector of void function
pointers to be executed.

The runtime must, before `main`, execute `_init`, all function pointers
in `.preinit_array`, then all function pointers in `.init_array`. The
runtime must also, at `exit`, execute all function pointers in
`.fini_array` in reverse, then execute `_fini`.

To assist in iterating through these arrays, GCC's internal linker
script defines the symbols `__(preinit,init,fini)_array_(start,end)` in
the appropriate sections marking the first function in each and the end
of the array.

[system-v-abi]: http://www.sco.com/developers/gabi/latest/ch4.sheader.html#special_sections

## The `_start` Symbol

Arguments to `_start` are on the stack for all platforms.
The top of the stack is structured as so:

* argument count
* array of argument pointers
* an empty string
* array of environment pointers
* a null terminator
* array of auxiliary vector entries
* an 'zero' auxiliary vector
* unspecified data

For simplicity, we simply pass a pointer to the stack to the C entry in
the runtime and dissasemble the stack there. The entry we use is as
follows:

```c
void __sel4_start_c(void *stack);
```

NOTE: `__sel4_start_c` is a void function as it should call the
non-returning `_exit` symbol after calling `main`.


