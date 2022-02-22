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
#include <ntos/gen_config.h>

.section .text
.global _KiSystemStartup
_KiSystemStartup:
	leal __stack_top, %esp
	mov  %esp, %ebp
	/*
	 * GCC expects that a C function is always entered via a call
	 * instruction and that the stack is 16-byte aligned before such an
	 * instruction (leaving it 16-byte aligned + 1 word from the
	 * implicit push when the function is entered).
	 *
	 * If additional items are pushed onto the stack, the stack must be
	 * manually re-aligned before before pushing the arguments for the
	 * call instruction to KiInitializeSystem.
	 */
	sub  $0x8, %esp
	push %ebp
	push %ebx
	call KiInitializeSystem

	/* should not return */
1:
	jmp  1b

.section .stack
.global __stack_base
.global __stack_top
__stack_base:
	.align 16
	.space CONFIG_NTOS_ROOT_STACK
__stack_top:
