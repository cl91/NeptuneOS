#pragma once

#include <stdarg.h>
#include <nt.h>

VOID vDbgPrint(PCSTR Format, va_list args);
VOID DbgPrint(PCSTR Format, ...);

#define DbgPrintFunc() DbgPrint("\n%s:\n", __func__)
