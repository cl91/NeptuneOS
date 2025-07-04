#pragma once

#define RTLP_DBGTRACE_MODULE_NAME	"NTPSX"

#include <nt.h>
#include <ntpsx.h>
#include <psxdll.h>
#include <services.h>
#include <sel4/sel4.h>
#include <ntdll_syssvc_gen.h>
#include <debug.h>
#include <util.h>

FORCEINLINE VOID RtlRaiseStatus(NTSTATUS Status)
{
    NtTerminateThread(NtCurrentProcess(), Status);
}

/* except.c */
VOID KiDispatchUserException(IN PEXCEPTION_RECORD ExceptionRecord,
			     IN PCONTEXT Context);
