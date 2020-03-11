#include <stdarg.h>
#include <printf.h>
#include <ke.h>
#include <rtl.h>

VOID KeBugCheckMsg(PCSTR Format, ...)
{
    va_list arglist;
    va_start(arglist, Format);
    vDbgPrint(Format, arglist);
    va_end(arglist);

    // Loop forever
    while (1);
}
