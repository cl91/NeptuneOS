#include <ntos.h>

VOID KiDumpThreadContext(IN PTHREAD_CONTEXT Context)
{
    HalVgaPrint("EAX %p\tEBX %p\tECX %p\tEDX %p\n"
		"EDI %p\tESI %p\tEBP %p\tESP %p\n"
		"EIP %p\tFS  %p\tGS  %p\tEFLAGS %p\n",
		(PVOID)Context->eax,
		(PVOID)Context->ebx,
		(PVOID)Context->ecx,
		(PVOID)Context->edx,
		(PVOID)Context->edi,
		(PVOID)Context->esi,
		(PVOID)Context->ebp,
		(PVOID)Context->esp,
		(PVOID)Context->eip,
		(PVOID)Context->fs_base,
		(PVOID)Context->gs_base,
		(PVOID)Context->eflags);
}
