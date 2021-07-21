#include <stdarg.h>
#include <printf.h>
#include <ntos.h>

VOID KeBugCheckMsg(PCSTR Format, ...)
{
    va_list arglist;
    va_start(arglist, Format);

#ifdef CONFIG_DEBUG_BUILD
    vDbgPrint(Format, arglist);
    /* Dump some useful information. */
    seL4_DebugDumpScheduler();
#endif

    va_end(arglist);

    /* Loop forever */
    while (1);
}
