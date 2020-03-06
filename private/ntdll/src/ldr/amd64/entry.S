.section .text
.global _LdrInitializeThunk
_LdrInitializeThunk:
	movq %rsp, %rbp
	movq %rsp, %rdi

	/*
	 * GCC expects that a C function is always entered via a call
	 * instruction and that the stack is 16-byte aligned before such an
	 * instruction (leaving it 16-byte aligned + 1 word from the
	 * implicit push when the function is entered).
	 *
	 * If additional items are pushed onto the stack, the stack must be
	 * manually re-aligned before the call instruction to
	 * LdrpInitialize.
	 */
	subq $0x8, %rsp
	push %rbp
	call LdrpInitialize

	/* should not return */
1:
	jmp  1b
