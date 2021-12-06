#include <ntos.h>

VOID KiDumpThreadContext(IN PTHREAD_CONTEXT Context)
{
    HalVgaPrint("RAX\t %p\tRBX\t%p\n"
		"RCX\t %p\tRDX\t%p\n"
		"RDI\t %p\tRSI\t%p\n"
		"RBP\t %p\tRSP\t%p\n"
		"R8\t %p\tR9\t%p\n"
		"R10\t %p\tR11\t%p\n"
		"R12\t %p\tR13\t%p\n"
		"R14\t %p\tR15\t%p\n"
		"RIP\t %p\tFS\t%p\n"
		"GS\t %p\tRFLAGS\t%p\n",
		(PVOID)Context->rax,
		(PVOID)Context->rbx,
		(PVOID)Context->rcx,
		(PVOID)Context->rdx,
		(PVOID)Context->rdi,
		(PVOID)Context->rsi,
		(PVOID)Context->rbp,
		(PVOID)Context->rsp,
		(PVOID)Context->r8,
		(PVOID)Context->r9,
		(PVOID)Context->r10,
		(PVOID)Context->r11,
		(PVOID)Context->r12,
		(PVOID)Context->r13,
		(PVOID)Context->r14,
		(PVOID)Context->r15,
		(PVOID)Context->rip,
		(PVOID)Context->fs_base,
		(PVOID)Context->gs_base,
		(PVOID)Context->rflags);
}
