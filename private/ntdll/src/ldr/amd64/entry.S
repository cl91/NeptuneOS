.section .text
.global LdrInitializeThunk
LdrInitializeThunk:
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

	/*
	 * The virtual address of the IPC buffer is in %rcx
	 */
	call LdrpInitialize

	/* should not return */
1:
	jmp  1b

/* Must match offset of SystemDllTlsRegion in TEB struct */
.global __tls_array
.equ __tls_array, 0x18
