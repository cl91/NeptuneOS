/*
 * LICENSE:         BSD - See COPYING.ARM in root directory
 * PROJECT:         ReactOS Client/Server Runtime SubSystem
 * FILE:            subsystems/win32/csrss/csrss.c
 * PURPOSE:         CSRSS Process Main Executable Code
 * PROGRAMMERS:     Alex Ionescu (alex@relsoft.net)
 *                  ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include <csrsrv.h>

/* FUNCTIONS ******************************************************************/

NTAPI VOID CsrpSetDefaultProcessHardErrorMode(VOID)
{
    ULONG DefaultHardErrorMode = 0;

    /* Disable hard errors */
    NtSetInformationProcess(NtCurrentProcess(), ProcessDefaultHardErrorMode,
			    &DefaultHardErrorMode, sizeof(DefaultHardErrorMode));
}

NTAPI VOID NtProcessStartup(PPEB Peb)
{
    KPRIORITY BasePriority = PROCESS_PRIORITY_NORMAL_FOREGROUND + 4;

    /* Set the base priority */
    NtSetInformationProcess(NtCurrentProcess(), ProcessBasePriority, &BasePriority,
			    sizeof(BasePriority));

    /* Initialize CSR through CSRSRV */
    PRTL_USER_PROCESS_PARAMETERS Params = Peb->ProcessParameters;
    NTSTATUS Status = CsrServerInitialization(&Params->CommandLine);
    if (!NT_SUCCESS(Status)) {
	/* Kill us */
	DPRINT1("CSRSS: Unable to initialize server, Status: 0x%08x\n", Status);
	NtTerminateProcess(NtCurrentProcess(), Status);
    }

    /* Disable errors */
    CsrpSetDefaultProcessHardErrorMode();

    /* If this is Session 0, make sure killing us bugchecks the system */
    RtlSetProcessIsCritical(TRUE, NULL, FALSE);

    /* Kill this thread. CSRSRV keeps us going */
    NtTerminateThread(NtCurrentThread(), Status);
}

/* EOF */
