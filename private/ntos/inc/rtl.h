#pragma once

#include <stdarg.h>
#include <nt.h>

#ifdef CONFIG_DEBUG_BUILD
VOID vDbgPrint(PCSTR Format, va_list args);
VOID DbgPrint(PCSTR Format, ...) __attribute__ ((format(printf, 1, 2)));
#else
#define DbgPrint(...)
#endif

#define DbgTrace(...) { DbgPrint("%s:  ", __func__); DbgPrint(__VA_ARGS__); }

/* Returns Ceil(x/y) for unsigned integers x and y */
#define RtlDivCeilUnsigned(x,y)	(((x)+(y)-1)/(y))
