#include "../ki.h"

VOID KiDumpThreadContext(IN PTHREAD_CONTEXT Context,
			 IN KI_DBG_PRINTER DbgPrinter)
{
    DbgPrinter("X0\t %p\tX1\t%p\n"
	       "X2\t %p\tX3\t%p\n"
	       "X4\t %p\tX5\t%p\n"
	       "X6\t %p\tX7\t%p\n"
	       "X8\t %p\tX9\t%p\n"
	       "X10\t %p\tX11\t%p\n"
	       "X12\t %p\tX13\t%p\n"
	       "X14\t %p\tX15\t%p\n"
	       "X16\t %p\tX17\t%p\n"
	       "X18\t %p\tX19\t%p\n"
	       "X20\t %p\tX21\t%p\n"
	       "X22\t %p\tX23\t%p\n"
	       "X24\t %p\tX25\t%p\n"
	       "X26\t %p\tX27\t%p\n"
	       "X28\t %p\tX29\t%p\n"
	       "X30\t %p\tSP\t%p\n"
	       "PC\t %p\tSPSR\t%p\n"
	       "TPIDR_EL0\t %p\tTPIDRRO_EL0\t%p\n",
	       (PVOID)Context->x0,
	       (PVOID)Context->x1,
	       (PVOID)Context->x2,
	       (PVOID)Context->x3,
	       (PVOID)Context->x4,
	       (PVOID)Context->x5,
	       (PVOID)Context->x6,
	       (PVOID)Context->x7,
	       (PVOID)Context->x8,
	       (PVOID)Context->x9,
	       (PVOID)Context->x10,
	       (PVOID)Context->x11,
	       (PVOID)Context->x12,
	       (PVOID)Context->x13,
	       (PVOID)Context->x14,
	       (PVOID)Context->x15,
	       (PVOID)Context->x16,
	       (PVOID)Context->x17,
	       (PVOID)Context->x18,
	       (PVOID)Context->x19,
	       (PVOID)Context->x20,
	       (PVOID)Context->x21,
	       (PVOID)Context->x22,
	       (PVOID)Context->x23,
	       (PVOID)Context->x24,
	       (PVOID)Context->x25,
	       (PVOID)Context->x26,
	       (PVOID)Context->x27,
	       (PVOID)Context->x28,
	       (PVOID)Context->x29,
	       (PVOID)Context->x30,
	       (PVOID)Context->sp,
	       (PVOID)Context->pc,
	       (PVOID)Context->spsr,
	       (PVOID)Context->tpidr_el0,
	       (PVOID)Context->tpidrro_el0);
}

VOID KiPopulateUserExceptionContext(IN PCONTEXT UserCtx,
				    IN PTHREAD_CONTEXT Ctx)
{
    UserCtx->ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    UserCtx->X0 = Ctx->x0;
    UserCtx->X1 = Ctx->x1;
    UserCtx->X2 = Ctx->x2;
    UserCtx->X3 = Ctx->x3;
    UserCtx->X4 = Ctx->x4;
    UserCtx->X5 = Ctx->x5;
    UserCtx->X6 = Ctx->x6;
    UserCtx->X7 = Ctx->x7;
    UserCtx->X8 = Ctx->x8;
    UserCtx->X9 = Ctx->x9;
    UserCtx->X10 = Ctx->x10;
    UserCtx->X11 = Ctx->x11;
    UserCtx->X12 = Ctx->x12;
    UserCtx->X13 = Ctx->x13;
    UserCtx->X14 = Ctx->x14;
    UserCtx->X15 = Ctx->x15;
    UserCtx->X16 = Ctx->x16;
    UserCtx->X17 = Ctx->x17;
    UserCtx->X18 = Ctx->x18;
    UserCtx->X19 = Ctx->x19;
    UserCtx->X20 = Ctx->x20;
    UserCtx->X21 = Ctx->x21;
    UserCtx->X22 = Ctx->x22;
    UserCtx->X23 = Ctx->x23;
    UserCtx->X24 = Ctx->x24;
    UserCtx->X25 = Ctx->x25;
    UserCtx->X26 = Ctx->x26;
    UserCtx->X27 = Ctx->x27;
    UserCtx->X28 = Ctx->x28;
    UserCtx->Fp = Ctx->x29;
    UserCtx->Lr = Ctx->x30;
    UserCtx->Sp = Ctx->sp;
    UserCtx->Pc = Ctx->pc;
    UserCtx->Cpsr = Ctx->spsr;
}
