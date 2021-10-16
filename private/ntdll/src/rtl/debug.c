#include <autoconf.h>
#include <sel4/sel4.h>
#include <stddef.h>
#include <stdarg.h>
#include <printf.h>
#include <nt.h>

// TODO: Replace with ReactOS code

#ifdef CONFIG_DEBUG_BUILD

VOID vDbgPrint(PCSTR Format, va_list args)
{
    char buf[512];
    vsnprintf(buf, sizeof(buf), Format, args);
    seL4_DebugPutString(buf);
}

VOID DbgPrint(PCSTR Format, ...)
{
    va_list arglist;
    va_start(arglist, Format);
    vDbgPrint(Format, arglist);
    va_end(arglist);
}

VOID _assert(PCSTR str, PCSTR file, unsigned int line)
{
    DbgPrint("Assertion %s failed at line %d of file %s\n",
	     str, line, file);
    /* Loop forever */
    while (1);
}

#else

VOID vDbgPrint(PCSTR Format, va_list args)
{
    /* DO nothing */
}

VOID DbgPrint(PCSTR Format, ...)
{
    /* Do nothing */
}

#endif

/*
 * For libsel4, required in both debug and release build.
 */
VOID __assert_fail(PCSTR str, PCSTR file, int line, PCSTR function)
{
    DbgPrint("Assertion %s failed in function %s at line %d of file %s\n",
	     str, function, line, file);
    /* Loop forever */
    while (1);
}
