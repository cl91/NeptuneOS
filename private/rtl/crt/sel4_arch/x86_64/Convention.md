<!--
     Copyright 2019, Data61
     Commonwealth Scientific and Industrial Research Organisation (CSIRO)
     ABN 41 687 119 230.

     This software may be distributed and modified according to the terms of
     the BSD 2-Clause license. Note that NO WARRANTY is provided.
     See "LICENSE_BSD2.txt" for details.

     @TAG(DATA61_BSD)
-->
# Calling Conventions for Intel 64

* `%rsp` contains the stack pointer,
* `%rbp` contains the frame pointer,
* `%rax` contains the return value, and
* `%rbx`and `%r12` to `%r15` are callee-save registers.

Additionally:

* The stack must always be 16-byte aligned, i.e. `%rsp` mod 16 == 0.

In order to ensure tha alignment is maintained at a 16-byte alignment,
the stack may need to be manually aligned after function entry.

When a function is entered via `call`, the return address is implicitly
pushed onto the stack, misaligning it by one word (8 bytes). When the
return stack pointer is then pushed onto the stack in the function
prologue, the stack is re-aligned.

Further pushes should occur in pairs or should be resolved using a
`subq` instruction to re-align the stack to 16 bytes.

It is also the responsibility of the caller to ensure that when a
function is called that the stack remains aligned to 16-bytes up to the
`call` instruction.

## Prologue

1. push `%rbp` onto the stack,
2. read the current value of `%rsp` into `%rbp`
3. Reserve the stack frame and re-align the stack to 16-bytes.

```asm
push %rbp
mov  %rsp, %rbp
// This will already be aligned to 16 bytes due to the empty stack
// frame.
// subq $0x0, %rsp
```

## Epilogue

```asm
leave
ret
```

## Argument Passing

Arguments are passed first using registers `%rdi`, `%rsi`, `%rdx`,
`%rcx`, `%r8`, `%r9`, `%xmm0`–`%xmm7`, then on the stack in
`%rbp+8+(8 * n)`
