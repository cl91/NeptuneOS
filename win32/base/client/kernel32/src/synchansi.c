/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            dll/win32/kernel32/client/synchansi.c
 * PURPOSE:         Synchronization functions (ANSI)
 */

/* INCLUDES ******************************************************************/

#include <k32.h>

/* FUNCTIONS ****************************************************************/

/*
 * @implemented
 */
WINAPI HANDLE CreateWaitableTimerA(IN LPSECURITY_ATTRIBUTES lpTimerAttributes OPTIONAL,
				   IN BOOL bManualReset, IN LPCSTR lpTimerName OPTIONAL)
{
    ConvertWin32AnsiObjectApiToUnicodeApi(WaitableTimer, lpTimerName, lpTimerAttributes,
					  bManualReset);
}

/*
 * @implemented
 */
WINAPI HANDLE OpenWaitableTimerA(IN DWORD dwDesiredAccess, IN BOOL bInheritHandle,
				 IN LPCSTR lpTimerName)
{
    ConvertOpenWin32AnsiObjectApiToUnicodeApi(WaitableTimer, dwDesiredAccess,
					      bInheritHandle, lpTimerName);
}

/*
 * @implemented
 */
WINAPI DECLSPEC_HOTPATCH HANDLE
CreateSemaphoreA(IN LPSECURITY_ATTRIBUTES lpSemaphoreAttributes OPTIONAL,
		 IN LONG lInitialCount, IN LONG lMaximumCount, IN LPCSTR lpName OPTIONAL)
{
    ConvertWin32AnsiObjectApiToUnicodeApi(Semaphore, lpName, lpSemaphoreAttributes,
					  lInitialCount, lMaximumCount);
}

/*
 * @implemented
 */
WINAPI DECLSPEC_HOTPATCH HANDLE OpenSemaphoreA(IN DWORD dwDesiredAccess,
					       IN BOOL bInheritHandle, IN LPCSTR lpName)
{
    ConvertOpenWin32AnsiObjectApiToUnicodeApi(Semaphore, dwDesiredAccess, bInheritHandle,
					      lpName);
}

/*
 * @implemented
 */
WINAPI DECLSPEC_HOTPATCH HANDLE OpenMutexA(IN DWORD dwDesiredAccess,
					   IN BOOL bInheritHandle, IN LPCSTR lpName)
{
    ConvertOpenWin32AnsiObjectApiToUnicodeApi(Mutex, dwDesiredAccess, bInheritHandle,
					      lpName);
}

/* EOF */
