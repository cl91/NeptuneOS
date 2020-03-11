#include <autoconf.h>
#include <sel4/sel4.h>
#include <nt.h>
#include <ke.h>
#include <stddef.h>
#include <stdarg.h>
#include <printf.h>

VOID vDbgPrint(PCSTR Format, va_list args)
{
#ifdef CONFIG_DEBUG_BUILD
    char buf[512];
    vsnprintf(buf, sizeof(buf), Format, args);
    for (const char *p = buf; p != NULL && *p != '\0'; p++) {
	seL4_DebugPutChar(*p);
    }
#endif
}

VOID DbgPrint(PCSTR Format, ...)
{
    va_list arglist;
    va_start(arglist, Format);
    vDbgPrint(Format, arglist);
    va_end(arglist);
}

VOID __assert_fail(PCSTR str, PCSTR file, int line, PCSTR function)
{
    KeBugCheckMsg("Assertion %s failed in function %s at line %s of file %s\n",
		  str, function, line, file);
}
