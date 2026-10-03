/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS System Libraries
 * FILE:            dll/win32/kernel32/include/console.h
 * PURPOSE:         Console API Client Definitions
 * PROGRAMMERS:     Hermes Belusca-Maito (hermes.belusca@sfr.fr)
 */

#pragma once

/* CONSTANTS ******************************************************************/

#define HANDLE_DETACHED_PROCESS     (HANDLE)-1
#define HANDLE_CREATE_NEW_CONSOLE   (HANDLE)-2
#define HANDLE_CREATE_NO_WINDOW     (HANDLE)-3


/* FUNCTION PROTOTYPES ********************************************************/

WINAPI BOOLEAN ConDllInitialize(IN ULONG Reason,
                 IN PWSTR SessionDir);

VOID
InitializeCtrlHandling(VOID);

WINAPI DWORD ConsoleControlDispatcher(IN LPVOID lpThreadParameter);

WINAPI DWORD PropDialogHandler(IN LPVOID lpThreadParameter);

WINAPI BOOL
GetConsoleHandleInformation(IN HANDLE hHandle,
                            OUT LPDWORD lpdwFlags);

WINAPI BOOL
SetConsoleHandleInformation(IN HANDLE hHandle,
                            IN DWORD dwMask,
                            IN DWORD dwFlags);

HANDLE
TranslateStdHandle(HANDLE hHandle);

VOID
SetTEBLangID(VOID);

VOID
SetUpConsoleInfo(IN BOOLEAN CaptureTitle,
                 IN OUT LPDWORD pTitleLength,
                 IN OUT LPWSTR* lpTitle OPTIONAL,
                 IN OUT LPDWORD pDesktopLength,
                 IN OUT LPWSTR* lpDesktop OPTIONAL,
                 IN OUT PCONSOLE_START_INFO ConsoleStartInfo);

VOID
SetUpHandles(IN PCONSOLE_START_INFO ConsoleStartInfo);

VOID
InitExeName(VOID);

VOID
SetUpAppName(IN BOOLEAN CaptureStrings,
             IN OUT LPDWORD CurDirLength,
             IN OUT LPWSTR* CurDir,
             IN OUT LPDWORD AppNameLength,
             IN OUT LPWSTR* AppName);

USHORT
GetCurrentExeName(OUT PWCHAR ExeName,
                  IN USHORT BufferSize);

LPCWSTR
IntCheckForConsoleFileName(IN LPCWSTR pszName,
                           IN DWORD dwDesiredAccess);

/* EOF */
