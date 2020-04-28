#pragma once

#include <stdarg.h>
#include <nt.h>

VOID vDbgPrint(PCSTR Format, va_list args);
VOID DbgPrint(PCSTR Format, ...);

#define DbgPrintFunc() DbgPrint("\n%s:\n", __func__)

/* Returns Ceil(x/y) for unsigned integers x and y */
#define RtlDivCeilUnsigned(x,y)	(((x)+(y)-1)/(y))
