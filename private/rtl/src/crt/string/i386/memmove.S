#ifdef _MSC_VER
#define memmove _memmove
#endif

.global memmove
#ifndef _MSC_VER
.type memmove,@function
#endif
memmove:
	mov 4(%esp),%eax
	sub 8(%esp),%eax
	cmp 12(%esp),%eax
#ifndef _MSC_VER
.hidden __memcpy_fwd
#endif
	jae __memcpy_fwd
	push %esi
	push %edi
	mov 12(%esp),%edi
	mov 16(%esp),%esi
	mov 20(%esp),%ecx
	lea -1(%edi,%ecx),%edi
	lea -1(%esi,%ecx),%esi
	std
	rep movsb
	cld
	lea 1(%edi),%eax
	pop %edi
	pop %esi
	ret
