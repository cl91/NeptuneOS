#include <ntdll.h>

VOID KiPopulateThreadContext(OUT PTHREAD_CONTEXT ThreadContext,
			     IN PCONTEXT Context)
{
    ThreadContext->eip = Context->Eip;
    ThreadContext->esp = Context->Esp;
    ThreadContext->eflags = Context->EFlags;
    ThreadContext->eax = Context->Eax;
    ThreadContext->ebx = Context->Ebx;
    ThreadContext->ecx = Context->Ecx;
    ThreadContext->edx = Context->Edx;
    ThreadContext->esi = Context->Esi;
    ThreadContext->edi = Context->Edi;
    ThreadContext->ebp = Context->Ebp;
    ThreadContext->fs_base = Context->SegFs;
    ThreadContext->gs_base = Context->SegGs;
}
