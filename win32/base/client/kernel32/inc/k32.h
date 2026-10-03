/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS System Libraries
 * FILE:            dll/win32/kernel32/k32.h
 * PURPOSE:         Win32 Kernel Library Header
 * PROGRAMMER:      Alex Ionescu (alex@relsoft.net)
 */

#ifndef __K32_H
#define __K32_H

/* INCLUDES ******************************************************************/

#include <stdio.h>

/* PSDK/NDK Headers */
#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include "winbasep.h"
#include <wingdi.h>
#include <winreg.h>
#include <wincon.h>
#include "winconp.h"
#include <winuser.h>

#undef TEXT
#define TEXT(s) L##s
#include <regstr.h>

#include <tlhelp32.h>

#include <nt.h>
#include <ntstrsafe.h>

/* CSRSS Headers */
#include <csr/csr.h>
#include <win/base.h>
#include <win/basemsg.h>
#include <win/console.h>
#include <win/conmsg.h>
#include <win/vdm.h>

/* DDK Driver Headers */
#include <mountmgr.h>

/* Internal Kernel32 Header */
#include "base.h"

/* Base Macros */
#include "base_x.h"

/* Console API Client Definitions */
#include "console.h"

/* Virtual DOS Machines (VDM) Support Definitions */
#include "vdm.h"

/* Undo hacks in wine_unicode.h */
#undef tolowerW
static inline WCHAR tolowerW(WCHAR ch)
{
    extern WINE_UNICODE_API const WCHAR wine_casemap_lower[];
    return ch + wine_casemap_lower[wine_casemap_lower[ch >> 8] + (ch & 0xff)];
}

#undef toupperW
static inline WCHAR toupperW(WCHAR ch)
{
    extern WINE_UNICODE_API const WCHAR wine_casemap_upper[];
    return ch + wine_casemap_upper[wine_casemap_upper[ch >> 8] + (ch & 0xff)];
}

/* Define to a function attribute for Microsoft hotpatch assembly prefix. */
#ifndef DECLSPEC_HOTPATCH
#if defined(_MSC_VER) || defined(__clang__)
/* FIXME: https://llvm.org/bugs/show_bug.cgi?id=10212 */
#define DECLSPEC_HOTPATCH
#else
#define DECLSPEC_HOTPATCH __attribute__((__ms_hook_prologue__))
#endif
#endif /* DECLSPEC_HOTPATCH */

FORCEINLINE LARGE_INTEGER KiReadSystemTime(_In_ volatile const KSYSTEM_TIME *SystemTime)
{
    LARGE_INTEGER Time;

#ifdef _WIN64
    /* Do a single atomic read */
    Time.QuadPart = *(volatile LONG64*)SystemTime;
#else
    /* Read in a loop until we get a match */
    for (;;)
    {
        Time.HighPart = SystemTime->High1Time;
        Time.LowPart = SystemTime->LowPart;
        if (Time.HighPart == SystemTime->High2Time)
            break;
        YieldProcessor();
    }
#endif
    return Time;
}

FORCEINLINE ULONG64 KiTickCountToMs(_In_ LARGE_INTEGER TickCount)
{
#ifdef _WIN64
    /* Native math is optimal on 64 bit */
    return (TickCount.QuadPart * SharedUserData->TickCountMultiplier) >> 24;
#else
    /* This is optimal on 32 bit (overflows after ~20,000 years) */
    ULONG Multiplier = SharedUserData->TickCountMultiplier;
    return (UInt32x32To64(TickCount.LowPart, Multiplier) >> 24) +
            UInt32x32To64(TickCount.HighPart << 8, Multiplier);
#endif
}

#endif /* __K32_H */
