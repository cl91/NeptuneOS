/*
 * PROJECT:         ReactOS NT Layer/System API
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            dll/ntdll/dbg/dbgui.c
 * PURPOSE:         Native Wrappers for the NT Debug Implementation
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 */

/* INCLUDES *****************************************************************/

#include <ntdll.h>

/* FUNCTIONS *****************************************************************/

/*
 * @implemented
 */
NTAPI NTSTATUS DbgUiConnectToDbg(VOID)
{
    OBJECT_ATTRIBUTES ObjectAttributes;

    /* Don't connect twice */
    if (NtCurrentTeb()->DbgSsReserved[1])
	return STATUS_SUCCESS;

    /* Setup the Attributes */
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, 0);

    /* Create the object */
    return NtCreateDebugObject(&NtCurrentTeb()->DbgSsReserved[1], DEBUG_OBJECT_ALL_ACCESS,
			       &ObjectAttributes, DBGK_KILL_PROCESS_ON_EXIT);
}

/*
 * @implemented
 */
NTAPI NTSTATUS DbgUiContinue(IN PCLIENT_ID ClientId, IN NTSTATUS ContinueStatus)
{
    /* Tell the kernel object to continue */
    return NtDebugContinue(NtCurrentTeb()->DbgSsReserved[1], ClientId, ContinueStatus);
}

/*
 * @implemented
 */
NTAPI NTSTATUS DbgUiWaitStateChange(OUT PDBGUI_WAIT_STATE_CHANGE WaitStateChange,
				    IN PLARGE_INTEGER TimeOut OPTIONAL)
{
    /* Tell the kernel to wait */
    return NtWaitForDebugEvent(NtCurrentTeb()->DbgSsReserved[1], TRUE, TimeOut,
			       WaitStateChange);
}

/*
 * @implemented
 */
NTAPI VOID DbgUiRemoteBreakin(VOID)
{
    /* Make sure a debugger is enabled; if so, breakpoint */
    if (NtCurrentPeb()->BeingDebugged)
	DbgBreakPoint();

    /* Exit the thread */
    RtlExitUserThread(STATUS_SUCCESS);
}

/*
 * @implemented
 */
NTAPI NTSTATUS DbgUiIssueRemoteBreakin(IN HANDLE Process)
{
    HANDLE hThread;
    CLIENT_ID ClientId;
    NTSTATUS Status;

    /* Create the thread that will do the breakin */
    Status = RtlCreateUserThread(Process, NULL, FALSE, 0, 0, PAGE_SIZE,
				 (PVOID)DbgUiRemoteBreakin, NULL, &hThread, &ClientId);

    /* Close the handle on success */
    if (NT_SUCCESS(Status))
	NtClose(hThread);

    /* Return status */
    return Status;
}

/*
 * @implemented
 */
NTAPI HANDLE DbgUiGetThreadDebugObject(VOID)
{
    /* Just return the handle from the TEB */
    return NtCurrentTeb()->DbgSsReserved[1];
}

/*
 * @implemented
 */
NTAPI VOID DbgUiSetThreadDebugObject(HANDLE DebugObject)
{
    /* Just set the handle in the TEB */
    NtCurrentTeb()->DbgSsReserved[1] = DebugObject;
}

/*
 * @implemented
 */
NTAPI NTSTATUS DbgUiDebugActiveProcess(IN HANDLE Process)
{
    NTSTATUS Status;

    /* Tell the kernel to start debugging */
    Status = NtDebugActiveProcess(Process, NtCurrentTeb()->DbgSsReserved[1]);
    if (NT_SUCCESS(Status)) {
	/* Now break-in the process */
	Status = DbgUiIssueRemoteBreakin(Process);
	if (!NT_SUCCESS(Status)) {
	    /* We couldn't break-in, cancel debugging */
	    DbgUiStopDebugging(Process);
	}
    }

    /* Return status */
    return Status;
}

/*
 * @implemented
 */
NTAPI NTSTATUS DbgUiStopDebugging(IN HANDLE Process)
{
    /* Call the kernel to remove the debug object */
    return NtRemoveProcessDebug(Process, NtCurrentTeb()->DbgSsReserved[1]);
}

/* EOF */
