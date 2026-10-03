/*
 * PROJECT:     ReactOS Client/Server Runtime SubSystem
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     CSR Client Library - API LPC Implementation
 * COPYRIGHT:   Copyright 2005-2012 Alex Ionescu <alex@relsoft.net>
 *              Copyright 2012-2022 Hermès Bélusca-Maïto
 * <hermes.belusca-maito@reactos.org>
 */

/* INCLUDES *******************************************************************/

#include "csrlib.h"

/* FUNCTIONS ******************************************************************/

/*
 * @implemented
 */
NTAPI NTSTATUS CsrNewThread(VOID)
{
    NTSTATUS Status;
    PTEB Teb = NtCurrentTeb();

    /* In clients this field records termination-port registration. Servers
     * retain their CSR_THREAD pointer and never use the client marker. */
    if (InsideCsrProcess || Teb->CsrClientThread == CSR_CLIENT_THREAD_REGISTERED)
	return STATUS_SUCCESS;

    /* Register the termination port to CSR's */
    Status = NtRegisterThreadTerminatePort(CsrApiPort);
    if (NT_SUCCESS(Status))
	Teb->CsrClientThread = CSR_CLIENT_THREAD_REGISTERED;
    return Status;
}

NTAPI BOOL DllMain(IN HINSTANCE hInstanceDll,
		   IN DWORD dwReason,
		   IN LPVOID lpReserved)
{
    /* We don't do much */
    UNREFERENCED_PARAMETER(hInstanceDll);
    UNREFERENCED_PARAMETER(dwReason);
    UNREFERENCED_PARAMETER(lpReserved);

    return TRUE;
}

/* EOF */
