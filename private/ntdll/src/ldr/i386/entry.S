.section .text
.global _LdrInitializeThunk
_LdrInitializeThunk:
	mov %esp, %ebp

	/*
	 * GCC expects that a C function is always entered via a call
	 * instruction and that the stack is 16-byte aligned before such an
	 * instruction (leaving it 16-byte aligned + 1 word from the
	 * implicit push when the function is entered).
	 *
	 * If additional items are pushed onto the stack, the stack must be
	 * manually re-aligned before before pushing the arguments for the
	 * call instruction to LdrpInitialize.
	 */
	sub  $0xc, %esp
	push %ebp
	call LdrpInitialize

	/* should not return */
1:
	jmp  1b