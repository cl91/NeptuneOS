#include "../ki.h"

VOID KiDumpThreadContext(IN PTHREAD_CONTEXT Context,
			 IN KI_DBG_PRINTER DbgPrinter)
{
    DbgPrinter("RAX\t %p\tRBX\t%p\n"
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

VOID KiPopulateUserExceptionContext(IN PCONTEXT UserCtx,
				    IN PTHREAD_CONTEXT Ctx)
{
    UserCtx->ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    UserCtx->EFlags = Ctx->rflags;
    UserCtx->FsBase = Ctx->fs_base;
    UserCtx->GsBase = Ctx->gs_base;
    UserCtx->Rax = Ctx->rax;
    UserCtx->Rcx = Ctx->rcx;
    UserCtx->Rdx = Ctx->rdx;
    UserCtx->Rbx = Ctx->rbx;
    UserCtx->Rsp = Ctx->rsp;
    UserCtx->Rbp = Ctx->rbp;
    UserCtx->Rsi = Ctx->rsi;
    UserCtx->Rdi = Ctx->rdi;
    UserCtx->R8 = Ctx->r8;
    UserCtx->R9 = Ctx->r9;
    UserCtx->R10 = Ctx->r10;
    UserCtx->R11 = Ctx->r11;
    UserCtx->R12 = Ctx->r12;
    UserCtx->R13 = Ctx->r13;
    UserCtx->R14 = Ctx->r14;
    UserCtx->R15 = Ctx->r15;
    UserCtx->Rip = Ctx->rip;
}
