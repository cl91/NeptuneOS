#include <stdarg.h>
#include "umtests.h"

VOID VgaPrint(IN PCSTR Format, ...)
{
    char buf[512];
    va_list arglist;
    va_start(arglist, Format);
    int n = _vsnprintf(buf, sizeof(buf), Format, arglist);
    va_end(arglist);
    if (n > 0) {
	NtDisplayStringA(buf);
    }
}
