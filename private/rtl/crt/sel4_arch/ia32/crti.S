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
.section .init
.global _init
_init:
	pushl %ebp
	movl  %esp, %ebp
	// Align the stack to 16-bytes after return address pushed by call
	// and the ebp pushed above.
	sub  $0x8, %esp

.section .fini
.global _fini
_fini:
	pushl %ebp
	movl  %esp, %ebp
	// Align the stack to 16-bytes after return address pushed by call
	// and the ebp pushed above.
	sub  $0x8, %esp
