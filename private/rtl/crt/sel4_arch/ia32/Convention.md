<!--
     Copyright 2019, Data61
     Commonwealth Scientific and Industrial Research Organisation (CSIRO)
     ABN 41 687 119 230.

     This software may be distributed and modified according to the terms of
     the BSD 2-Clause license. Note that NO WARRANTY is provided.
     See "LICENSE_BSD2.txt" for details.

     @TAG(DATA61_BSD)
-->
# Calling Conventions for IA-32

* `%esp` contains the stack pointer,
* `%ebp` contains the frame pointer,
* `%eax` contains the return value, and
* `%ebx`, `%esi`, and `%edi` are callee-save registers.

Additionally:

* The stack must always be 16-byte aligned, i.e. `%esp` mod 16 == 0.

In order to ensure tha alignment is maintained at a 16-byte alignment,
the stack may need to be manually aligned after function entry.

When a function is entered via `call`, the return address is implicitly
pushed onto the stack, misaligning it by one word (4 bytes). When the
return stack pointer is then pushed onto the stack in the function
prologue, the stack then becomes misaligned by two words (8 bytes).

Further pushes should occur in pairs or should be resolved using a
`sub` instruction to re-align the stack to 16 bytes.

It is also the responsibility of the caller to ensure that when a
function is called that the stack remains aligned to 16-bytes up to the
`call` instruction. As the callee removes arguments from the stack upon
return, the stack may be misaligned when a function is returned from. It
is the responsibility of the caller to re-align the stack if this
occurs.

## Prologue

1. push `%ebp` onto the stack,
2. read the current value of `%esp` into `%ebp`
3. Reserve the stack frame and re-align the stack to 16-bytes.

```asm
push %ebp
mov  %esp, %ebp
// re-align to 16-bytes
sub  $0x8, %esp
```

## Epilogue

```asm
leave
ret
```

## Argument Passing

Arguments are passed on the stack in `%ebp+4+(4 * n)` (between the
return address and the return frame pointer).
