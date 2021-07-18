#include <stdarg.h>
#include <printf.h>
#include <ntos.h>

VOID KeBugCheckMsg(PCSTR Format, ...)
{
    va_list arglist;
    va_start(arglist, Format);
    vDbgPrint(Format, arglist);
    va_end(arglist);

    /* Dump some useful information. */
    seL4_DebugDumpScheduler();

    /* Loop forever */
    while (1);
}
