#pragma once

#define RTLP_DBGTRACE_MODULE_NAME	"NTDLL"

#include <string.h>
#include <stdint.h>
#include <nt.h>
#include <excpt.h>
#include <services.h>
#include <sel4/sel4.h>
#include <ntdll_syssvc_gen.h>
#include <debug.h>
#include <assert.h>
#include <image.h>
#include <util.h>

#define CDECL		__cdecl

#undef DPRINT
#undef DPRINT1
#define DPRINT DbgTrace
#define DPRINT1 DbgTrace

#define ROUND_DOWN(x, align)	ALIGN_DOWN_BY(x, align)
#define ROUND_UP(x, align)	ALIGN_UP_BY(x, align)

/* We cannot include win32 headers so define ULongToPtr here */
static inline void *ULongToPtr(const unsigned long ul)
{
    return (void*)((ULONG_PTR)ul);
}
#define UlongToPtr ULongToPtr

static inline unsigned long PtrToUlong(const void *p)
{
    return ((unsigned long)(ULONG_PTR)p);
}

#define SharedUserData ((KUSER_SHARED_DATA *CONST) KUSER_SHARED_DATA_CLIENT_ADDR)

/* rtl/exception.c */
VOID RtlpPrintStackTrace(IN PEXCEPTION_POINTERS ExceptionInfo,
			 IN BOOLEAN Unhandled);
VOID RtlpVgaPrintStackTrace(IN PEXCEPTION_POINTERS ExceptionInfo,
			    IN BOOLEAN Unhandled);
