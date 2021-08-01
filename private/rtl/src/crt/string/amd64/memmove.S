.global memmove
#ifndef _MSC_VER
.type memmove,@function
#endif
memmove:
	mov %rdi,%rax
	sub %rsi,%rax
	cmp %rdx,%rax
#ifndef _MSC_VER
.hidden __memcpy_fwd
#endif
	jae __memcpy_fwd
	mov %rdx,%rcx
	lea -1(%rdi,%rdx),%rdi
	lea -1(%rsi,%rdx),%rsi
	std
	rep movsb
	cld
	lea 1(%rdi),%rax
	ret
