/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Base API Server DLL
 * FILE:            subsystems/win/basesrv/sndsntry.c
 * PURPOSE:         Sound Sentry Notifications
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 */

/* INCLUDES *******************************************************************/

#include "basesrv.h"

/* GLOBALS ********************************************************************/

typedef BOOL (NTAPI *PUSER_SOUND_SENTRY)(VOID);
NTAPI BOOL FirstSoundSentry(VOID);

static PUSER_SOUND_SENTRY _UserSoundSentry = FirstSoundSentry;

/* PRIVATE FUNCTIONS **********************************************************/

NTAPI BOOL FailSoundSentry(VOID)
{
    /* In case the function can't be found/is unimplemented */
    return FALSE;
}

NTAPI BOOL FirstSoundSentry(VOID)
{
    UNICODE_STRING DllString = RTL_CONSTANT_STRING(L"winsrv");
    STRING FuncString = RTL_CONSTANT_STRING("_UserSoundSentry");
    HANDLE DllHandle;
    NTSTATUS Status;
    PUSER_SOUND_SENTRY NewSoundSentry = FailSoundSentry;

    /* Load winsrv manually */
    Status = LdrGetDllHandle(NULL, NULL, &DllString, &DllHandle);
    if (NT_SUCCESS(Status)) {
	/* If it was found, get SoundSentry export */
	Status = LdrGetProcedureAddress(DllHandle, &FuncString, 0,
					(PVOID *)&NewSoundSentry);
    }

    /* Set it as the callback for the future, and call it */
    _UserSoundSentry = NewSoundSentry;
    return _UserSoundSentry();
}

/* PUBLIC SERVER APIS *********************************************************/

CSR_API(BaseSrvSoundSentryNotification)
{
    /* Call the API and see if it succeeds */
    return (_UserSoundSentry() ? STATUS_SUCCESS : STATUS_ACCESS_DENIED);
}

/* EOF */
