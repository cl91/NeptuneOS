#include <ntdll.h>

VOID KiPopulateThreadContext(OUT PTHREAD_CONTEXT ThreadContext,
			     IN PCONTEXT Context)
{
    ThreadContext->pc = Context->Pc;
    ThreadContext->sp = Context->Sp;
    ThreadContext->spsr = Context->Cpsr;
    ThreadContext->x0 = Context->X0;
    ThreadContext->x1 = Context->X1;
    ThreadContext->x2 = Context->X2;
    ThreadContext->x3 = Context->X3;
    ThreadContext->x4 = Context->X4;
    ThreadContext->x5 = Context->X5;
    ThreadContext->x6 = Context->X6;
    ThreadContext->x7 = Context->X7;
    ThreadContext->x8 = Context->X8;
    ThreadContext->x9 = Context->X9;
    ThreadContext->x10 = Context->X10;
    ThreadContext->x11 = Context->X11;
    ThreadContext->x12 = Context->X12;
    ThreadContext->x13 = Context->X13;
    ThreadContext->x14 = Context->X14;
    ThreadContext->x15 = Context->X15;
    ThreadContext->x16 = Context->X16;
    ThreadContext->x17 = Context->X17;
    ThreadContext->x18 = Context->X18;
    ThreadContext->x19 = Context->X19;
    ThreadContext->x20 = Context->X20;
    ThreadContext->x21 = Context->X21;
    ThreadContext->x22 = Context->X22;
    ThreadContext->x23 = Context->X23;
    ThreadContext->x24 = Context->X24;
    ThreadContext->x25 = Context->X25;
    ThreadContext->x26 = Context->X26;
    ThreadContext->x27 = Context->X27;
    ThreadContext->x28 = Context->X28;
    ThreadContext->x29 = Context->Fp;
    ThreadContext->x30 = Context->Lr;
    ThreadContext->tpidr_el0 = Context->X18;
    ThreadContext->tpidrro_el0 = 0;
}
