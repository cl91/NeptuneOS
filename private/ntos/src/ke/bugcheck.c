#include <stdarg.h>
#include <printf.h>
#include <ntos.h>

static VOID KiPrintHaltMsg(PCSTR Format, va_list arglist)
{
#ifdef CONFIG_DEBUG_BUILD
    vDbgPrint(Format, arglist);
    /* Dump some useful information. */
    seL4_DebugDumpScheduler();
#endif
    char buf[512];
    vsnprintf(buf, sizeof(buf), Format, arglist);
    KeVgaWriteString(buf);
}

VOID KiHaltSystem(IN PCSTR Format, ...)
{
    va_list arglist;
    va_start(arglist, Format);
    KiPrintHaltMsg(Format, arglist);
    va_end(arglist);

    /* Loop forever */
    while (1);
}

VOID KeBugCheck(IN PCSTR Function,
		IN PCSTR File,
		IN ULONG Line,
		IN ULONG Error)
{
    KiHaltSystem("Unrecoverable error at %s @ %s line %d: Error Code 0x%x. System halted.\n",
		 Function, File, Line, Error);
}

VOID KeBugCheckMsg(IN PCSTR Format, ...)
{
    va_list arglist;
    va_start(arglist, Format);
    KiPrintHaltMsg(Format, arglist);
    va_end(arglist);

    /* Loop forever */
    while (1);
}
