/*
 * COPYRIGHT:         See COPYING in the top level directory
 * PROJECT:           ReactOS Run-Time Library
 * PURPOSE:           User-mode exception support for IA-32
 * FILE:              lib/rtl/i386/except.c
 * PROGRAMERS:        Alex Ionescu (alex@relsoft.net)
 *                    Casper S. Hornstrup (chorns@users.sourceforge.net)
 */

/* INCLUDES *****************************************************************/

#include <ntdll.h>

/* PUBLIC FUNCTIONS **********************************************************/

VOID NTAPI RtlUnwind(IN PVOID TargetFrame OPTIONAL,
		     IN PVOID TargetIp OPTIONAL,
		     IN PEXCEPTION_RECORD ExceptionRecord OPTIONAL,
		     IN PVOID ReturnValue)
{
    /* TODO */
}
