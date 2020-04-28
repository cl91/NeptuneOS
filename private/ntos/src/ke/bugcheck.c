#include <stdarg.h>
#include <printf.h>
#include <ntos.h>

VOID KeBugCheckMsg(PCSTR Format, ...)
{
    va_list arglist;
    va_start(arglist, Format);
    vDbgPrint(Format, arglist);
    va_end(arglist);

    // Loop forever
    while (1);
}
