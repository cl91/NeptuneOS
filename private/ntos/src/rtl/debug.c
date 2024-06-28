#include <autoconf.h>
#include <sel4/sel4.h>
#include <nt.h>
#include <ke.h>
#include <stdarg.h>
#include <printf.h>

#ifdef CONFIG_DEBUG_BUILD

VOID vDbgPrint(PCSTR Format, va_list args)
{
    char buf[512];
    vsnprintf(buf, sizeof(buf), Format, args);
    seL4_DebugPutString(buf);
}

ULONG DbgPrint(PCSTR Format, ...)
{
    va_list arglist;
    va_start(arglist, Format);
    vDbgPrint(Format, arglist);
    va_end(arglist);
    return 0;
}

VOID _assert(PCSTR str, PCSTR file, unsigned int line)
{
    KeBugCheckMsg("Assertion %s failed at line %d of file %s\n",
		  str, line, file);
    /* Loop forever */
    while (1) ;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wframe-address"
extern char _text_start[];
#define GET_RETURN_ADDRESS(i)				\
    ReturnAddresses[i] = __builtin_return_address(i+1);	\
    if (ReturnAddresses[i] < (PVOID)_text_start) {	\
	goto out;					\
    }
NTAPI ULONG RtlAssert(IN PVOID FailedAssertion,
		      IN PVOID FileName,
		      IN ULONG LineNumber,
		      IN OPTIONAL PCHAR Message)
{
    PVOID ReturnAddresses[8] = {};
    GET_RETURN_ADDRESS(0);
    GET_RETURN_ADDRESS(1);
    GET_RETURN_ADDRESS(2);
    GET_RETURN_ADDRESS(3);
    GET_RETURN_ADDRESS(4);
    GET_RETURN_ADDRESS(5);
    GET_RETURN_ADDRESS(6);
    GET_RETURN_ADDRESS(7);
out:
    KeBugCheckMsg("Assertion %s failed at line %d of file %s%s%s.\n"
		  "Call stack: %p %p %p %p %p %p %p %p\n",
		  (PCSTR)FailedAssertion, LineNumber, (PCSTR)FileName,
		  Message ? ": " : "", Message ? Message : "",
		  ReturnAddresses[0], ReturnAddresses[1],
		  ReturnAddresses[2], ReturnAddresses[3],
		  ReturnAddresses[4], ReturnAddresses[5],
		  ReturnAddresses[6], ReturnAddresses[7]);
    /* Loop forever */
    while (1);
    return 0;
}
#pragma GCC diagnostic pop
#endif

/*
 * libsel4 requires this, even for release build. The _assert function above
 * is for the crt assert.h, which is only needed in debug build.
 */
VOID __assert_fail(PCSTR str, PCSTR file, int line, PCSTR function)
{
    KeBugCheckMsg("Assertion %s failed in function %s at line %d of file %s\n",
		  str, function, line, file);
    /* Loop forever */
    while (1) ;
}
