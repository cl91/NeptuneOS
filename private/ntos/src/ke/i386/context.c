#include "../ki.h"

VOID KiDumpThreadContext(IN PTHREAD_CONTEXT Context,
    			 IN KI_DBG_PRINTER DbgPrinter)
{
    DbgPrinter("EAX %p\tEBX %p\tECX %p\tEDX %p\n"
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

VOID KiPopulateUserExceptionContext(IN PCONTEXT UserCtx,
				    IN PTHREAD_CONTEXT Ctx)
{
    UserCtx->ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    UserCtx->FsBase = Ctx->fs_base;
    UserCtx->GsBase = Ctx->gs_base;
    UserCtx->Edi = Ctx->edi;
    UserCtx->Esi = Ctx->esi;
    UserCtx->Ebx = Ctx->ebx;
    UserCtx->Edx = Ctx->edx;
    UserCtx->Ecx = Ctx->ecx;
    UserCtx->Eax = Ctx->eax;
    UserCtx->Ebp = Ctx->ebp;
    UserCtx->Eip = Ctx->eip;
    UserCtx->EFlags = Ctx->eflags;
    UserCtx->Esp = Ctx->esp;
}
