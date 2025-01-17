#include <ntdll.h>

VOID KiPopulateThreadContext(OUT PTHREAD_CONTEXT ThreadContext,
			     IN PCONTEXT Context)
{
    ThreadContext->rip = Context->Rip;
    ThreadContext->rsp = Context->Rsp;
    ThreadContext->rflags = Context->EFlags;
    ThreadContext->rax = Context->Rax;
    ThreadContext->rbx = Context->Rbx;
    ThreadContext->rcx = Context->Rcx;
    ThreadContext->rdx = Context->Rdx;
    ThreadContext->rsi = Context->Rsi;
    ThreadContext->rdi = Context->Rdi;
    ThreadContext->rbp = Context->Rbp;
    ThreadContext->r8 = Context->R8;
    ThreadContext->r9 = Context->R9;
    ThreadContext->r10 = Context->R10;
    ThreadContext->r11 = Context->R11;
    ThreadContext->r12 = Context->R12;
    ThreadContext->r13 = Context->R13;
    ThreadContext->r14 = Context->R14;
    ThreadContext->r15 = Context->R15;
}
