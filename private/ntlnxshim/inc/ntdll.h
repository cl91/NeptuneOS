#pragma once

#ifdef KRNLMODE
#define RTLP_DBGTRACE_MODULE_NAME	"NTLNXSHIMK"
#else
#define RTLP_DBGTRACE_MODULE_NAME	"NTLNXSHIMU"
#endif

#include <nt.h>
#include <services.h>
#include <sel4/sel4.h>
#include <ntdll_syssvc_gen.h>
#include <debug.h>
#include <util.h>

typedef struct _TEB {
    NT_TIB NtTib;
    struct {
	MWORD ServiceCap;
    } Wdm;
} TEB, *PTEB;

FORCEINLINE NTAPI PTEB NtCurrentTeb(VOID)
{
    return (PVOID)NtCurrentTib();
}
