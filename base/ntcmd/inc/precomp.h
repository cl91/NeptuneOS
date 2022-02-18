/*++

Copyright (c) Alex Ionescu.  All rights reserved.

    THIS CODE AND INFORMATION IS PROVIDED UNDER THE LESSER GNU PUBLIC LICENSE.
    PLEASE READ THE FILE "COPYING" IN THE TOP LEVEL DIRECTORY.

Module Name:

    precomp.h

Abstract:

    The Native Command Line Interface (NCLI) is the command shell for the
    TinyKRNL OS.

Environment:

    Native mode

Revision History:

    Alex Ionescu - Started Implementation - 23-Mar-06

--*/

#define WIN32_NO_STATUS
#define NTOS_MODE_USER

#include <nt.h>
#include <stdio.h>
#include <stdarg.h>
#include <wchar.h>
#include <excpt.h>
#include <ntddkbd.h>
#include "ntfile.h"
#include "ntreg.h"

//
// Device type for input/output
//
typedef enum _CON_DEVICE_TYPE {
    KeyboardType,
    MouseType
} CON_DEVICE_TYPE;

//
// Display functions
//
NTSTATUS RtlCliDisplayString(IN PCH Message, ...);

NTSTATUS RtlCliPrintString(IN PUNICODE_STRING Message);

NTSTATUS RtlCliPutChar(IN WCHAR Char);

//
// Input functions
//
NTSTATUS RtlCliOpenInputDevice(OUT PHANDLE Handle, IN CON_DEVICE_TYPE Type);

CHAR RtlCliGetChar(IN HANDLE hDriver);

PCHAR RtlCliGetLine(IN HANDLE hDriver);

//
// System information functions
//
NTSTATUS RtlCliListDrivers(VOID);

NTSTATUS RtlCliListProcesses(VOID);

NTSTATUS RtlCliDumpSysInfo(VOID);

NTSTATUS RtlCliShutdown(VOID);

NTSTATUS RtlCliReboot(VOID);

NTSTATUS RtlCliPowerOff(VOID);

//
// Hardware functions
//
NTSTATUS RtlCliListHardwareTree(VOID);

//
// File functions
//
NTSTATUS RtlCliListDirectory(VOID);

NTSTATUS RtlCliSetCurrentDirectory(PCHAR Directory);

ULONG RtlCliGetCurrentDirectory(IN OUT PWSTR CurrentDirectory);

// Keyboard:

extern HANDLE hKeyboard;

typedef struct _KBD_RECORD {
    USHORT wVirtualScanCode;
    ULONG dwControlKeyState;
    UCHAR AsciiChar;
    BOOLEAN bKeyDown;
} KBD_RECORD, *PKBD_RECORD;

void IntTranslateKey(PKEYBOARD_INPUT_DATA InputData, KBD_RECORD * kbd_rec);

#define RIGHT_ALT_PRESSED     0x0001	// the right alt key is pressed.
#define LEFT_ALT_PRESSED      0x0002	// the left alt key is pressed.
#define RIGHT_CTRL_PRESSED    0x0004	// the right ctrl key is pressed.
#define LEFT_CTRL_PRESSED     0x0008	// the left ctrl key is pressed.
#define SHIFT_PRESSED         0x0010	// the shift key is pressed.
#define NUMLOCK_ON            0x0020	// the numlock light is on.
#define SCROLLLOCK_ON         0x0040	// the scrolllock light is on.
#define CAPSLOCK_ON           0x0080	// the capslock light is on.
#define ENHANCED_KEY          0x0100	// the key is enhanced.

// Process:

NTSTATUS CreateNativeProcess(IN PCWSTR file_name, IN PCWSTR cmd_line,
			     OUT PHANDLE hProcess);

#define BUFFER_SIZE 1024

// Command processing:

UINT StringToArguments(CHAR *str);

extern char *xargv[BUFFER_SIZE];
extern unsigned int xargc;

BOOL GetFullPath(IN PCSTR filename,
		 OUT PWSTR out,
		 IN ULONG out_size,
		 IN BOOL add_slash);
BOOL FileExists(PCWSTR fname);

// Registry

NTSTATUS OpenKey(OUT PHANDLE pHandle, IN PWCHAR key);
NTSTATUS RegWrite(HANDLE hKey, INT type, PWCHAR key_name, PVOID data,
		  DWORD size);

NTSTATUS RegReadValue(HANDLE hKey, PWCHAR key_name, OUT PULONG type,
		      OUT PVOID data, IN ULONG buf_size,
		      OUT PULONG out_size);

// Misc

void FillUnicodeStringWithAnsi(OUT PUNICODE_STRING us, IN PCHAR as);

//===========================================================
//
// Helper Functions for ntreg.c
//
//===========================================================

BOOLEAN SetUnicodeString(UNICODE_STRING * pustrRet, WCHAR * pwszData);
BOOLEAN DisplayString(WCHAR * pwszData);
HANDLE InitHeapMemory(void);
BOOLEAN DeinitHeapMemory(HANDLE hHeap);
BOOLEAN AppendString(WCHAR * pszInput, WCHAR * pszAppend);
UINT GetStringLength(WCHAR * pszInput);
