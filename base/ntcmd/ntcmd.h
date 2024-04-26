/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Module Name:

    ntcmd.h

Abstract:

    This is the master header file for the Native Command Prompt, the command shell
    for Neptune OS.

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

//
// Device type for input/output
//
typedef enum _CON_DEVICE_TYPE {
    KeyboardType,
    MouseType
} CON_DEVICE_TYPE;

//
// Keyboard code
//
#define RIGHT_ALT_PRESSED     0x0001	// the right alt key is pressed.
#define LEFT_ALT_PRESSED      0x0002	// the left alt key is pressed.
#define RIGHT_CTRL_PRESSED    0x0004	// the right ctrl key is pressed.
#define LEFT_CTRL_PRESSED     0x0008	// the left ctrl key is pressed.
#define SHIFT_PRESSED         0x0010	// the shift key is pressed.
#define NUMLOCK_ON            0x0020	// the numlock light is on.
#define SCROLLLOCK_ON         0x0040	// the scrolllock light is on.
#define CAPSLOCK_ON           0x0080	// the capslock light is on.
#define ENHANCED_KEY          0x0100	// the key is enhanced.

typedef struct _KBD_RECORD {
    USHORT wVirtualScanCode;
    ULONG dwControlKeyState;
    UCHAR AsciiChar;
    BOOLEAN bKeyDown;
} KBD_RECORD, *PKBD_RECORD;

extern HANDLE hKeyboard;

//
// Registry key
//
#define HKEY_CLASSES_ROOT           0x80000000
#define HKEY_CURRENT_USER           0x80000001
#define HKEY_LOCAL_MACHINE          0x80000002
#define HKEY_USERS                  0x80000003
#define HKEY_PERFORMANCE_DATA       0x80000004
#define HKEY_PERFORMANCE_TEXT       0x80000050
#define HKEY_PERFORMANCE_NLSTEXT    0x80000060
#define HKEY_CURRENT_CONFIG         0x80000005
#define HKEY_DYN_DATA               0x80000006

typedef ULONG H_KEY;

//
// Display functions
//
NTSTATUS RtlCliDisplayString(IN PCH Message, ...);
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
NTSTATUS GetFullPath(IN PCSTR FileName,
		     OUT PWSTR FullPath,
		     IN ULONG FullPathSize,
		     IN BOOL AddSlash);
BOOL FileExists(PCWSTR FileName);

NTSTATUS OpenFile(HANDLE *RetFile, WCHAR *FileName,
		  BOOLEAN Write, BOOLEAN Overwrite);
NTSTATUS OpenDirectory(HANDLE *RetFile, WCHAR *FileName,
		       BOOLEAN Write, BOOLEAN Overwrite);
NTSTATUS ReadFile(HANDLE File, PVOID OutBuffer,
		  ULONG BufferSize, ULONG *ReturnedLength);
NTSTATUS WriteFile(HANDLE File, PVOID Data, ULONG BufferSize,
		   ULONG *ReturnedLength);
NTSTATUS SeekFile(HANDLE File, LONGLONG Amount);
NTSTATUS GetFilePosition(HANDLE File,
			 LONGLONG *CurrentPosition);
NTSTATUS GetFileSize(HANDLE File, LONGLONG *FileSize);
VOID CloseFile(HANDLE File);
NTSTATUS CopyFile(WCHAR *Src, WCHAR *Dest);
NTSTATUS DeleteFile(PCWSTR FileName);
NTSTATUS CreateDirectory(PCWSTR DirName);
NTSTATUS MoveFile(IN PCWSTR ExistingFileName,
		  IN PCWSTR NewFileName, BOOLEAN ReplaceIfExists);

//
// Keyboard functions
//
VOID IntTranslateKey(PKEYBOARD_INPUT_DATA InputData, KBD_RECORD *kbd_rec);

//
// Process functions
//
NTSTATUS CreateNativeProcess(IN PCWSTR file_name, IN PCWSTR cmd_line,
			     OUT PHANDLE hProcess);

//
// Command processing function
//
UINT StringToArguments(IN OUT CHAR *Cmd, IN ULONG Bufsize, IN ULONG MaxArgs,
		       OUT PCHAR *ArgList);

//
// Registry functions
//
NTSTATUS OpenKey(OUT PHANDLE pHandle, IN PWCHAR key);
NTSTATUS RegWrite(HANDLE hKey, INT type, PWCHAR key_name, PVOID data,
		  DWORD size);
NTSTATUS RegReadValue(HANDLE hKey, PWCHAR key_name, OUT PULONG type,
		      OUT PVOID data, IN ULONG buf_size,
		      OUT PULONG out_size);

WCHAR *NtRegGetRootPath(H_KEY hkRoot);
BOOLEAN NtRegOpenKey(HANDLE *phKey, H_KEY hkRoot, WCHAR *pwszSubKey,
		     ACCESS_MASK DesiredAccess);
BOOLEAN NtRegWriteValue(HANDLE H_KEY, WCHAR *pwszValueName, PVOID pData,
			ULONG uLength, ULONG dwRegType);
BOOLEAN NtRegWriteString(HANDLE H_KEY, WCHAR *pwszValueName,
			 WCHAR *pwszValue);
BOOLEAN NtRegDeleteValue(HANDLE H_KEY, WCHAR *pwszValueName);
BOOLEAN NtRegCloseKey(HANDLE H_KEY);
BOOLEAN NtRegReadValue(HANDLE H_KEY, HANDLE hHeapHandle,
		       WCHAR *pszValueName,
		       PKEY_VALUE_PARTIAL_INFORMATION *pRetBuffer,
		       ULONG *pRetBufferSize);
VOID NtEnumKey(HANDLE hKey);

//
// Misc functions
//
NTSTATUS FillUnicodeStringWithAnsi(OUT PUNICODE_STRING UnicodeString, IN PCHAR String);
PCSTR RtlCliStatusToErrorMessage(IN NTSTATUS Status);

//
// Helper Functions for ntreg.c
//
HANDLE InitHeapMemory(VOID);
BOOLEAN DeinitHeapMemory(HANDLE hHeap);
BOOLEAN AppendString(WCHAR *pszInput, WCHAR *pszAppend);
UINT GetStringLength(WCHAR *pszInput);
