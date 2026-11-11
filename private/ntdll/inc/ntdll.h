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
#include <timesvc.h>

#define CDECL		__cdecl

#undef DPRINT
#undef DPRINT1
#if DBG
#define DPRINT DbgTrace
#define DPRINT1 DbgTrace
#else  /* !DBG */
#define DPRINT(...)
#define DPRINT1(...)
#ifdef DbgPrint
#undef DbgPrint
#endif
#define DbgPrint(...)
#endif	/* DBG */

/* ke/time.c */
VOID KiInitTime(VOID);

/* rtl/exception.c */
#if DBG
VOID RtlpPrintStackTrace(IN PEXCEPTION_POINTERS ExceptionInfo,
			 IN BOOLEAN Unhandled);
#else
#define RtlpPrintStackTrace(...)
#endif
VOID RtlpVgaPrintStackTrace(IN PEXCEPTION_POINTERS ExceptionInfo,
			    IN BOOLEAN Unhandled);

/*
 * Debug Service calls
 */
NTAPI ULONG DebugService(IN ULONG Service, IN PVOID Argument1, IN PVOID Argument2,
			 IN PVOID Argument3, IN PVOID Argument4);

NTAPI VOID DebugService2(IN PVOID Argument1, IN PVOID Argument2, IN ULONG Service);
