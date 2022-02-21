/*++

Copyright (c) Alex Ionescu.  All rights reserved.
Copyright (c) 2011 amdf.

    THIS CODE AND INFORMATION IS PROVIDED UNDER THE LESSER GNU PUBLIC LICENSE.
    PLEASE READ THE FILE "COPYING" IN THE TOP LEVEL DIRECTORY.

Module Name:

    main.c

Abstract:

    The Native Command Line Interface (NCLI) is the command shell for the
    TinyKRNL OS.
    This module handles the main command line interface and command parsing.

Environment:

    Native mode

Revision History:

    Alex Ionescu - Started Implementation - 01-Mar-06
    Alex Ionescu - Reworked architecture - 23-Mar-06
    amdf         - Added process launch command - 25-Jan-11
    amdf         - Added move command - 20-Feb-11

--*/
#include "precomp.h"

HANDLE hKeyboard;
HANDLE hHeap;
HANDLE hKey;

#define NTCMD_BANNER "Neptune OS Native Command Prompt [Version " VER_PRODUCTVERSION_STRING "]\n"

PCSTR helpstr =
    "\n"
    "cd X     - Change directory to X    md X     - Make directory X\n"
    "copy X Y - Copy file X to Y         poweroff - Power off PC\n"
    "dir      - Show directory contents  pwd      - Print working directory\n"
    "del X    - Delete file X            reboot   - Reboot PC\n"
    "devtree  - Dump device tree         shutdown - Shutdown PC\n"
    "exit     - Exit shell               sysinfo  - Dump system information\n"
    "lm       - List modules             vid      - Test screen output\n"
    "lp       - List processes           move X Y - Move file X to Y\n"
    "\n"
    "If a command is not in the list, it is treated as an executable name\n"
    "\n"
    "Note: we haven't implemented file system yet so pretty much none of the\n"
    "commands above works right now. However, the keyboard stack is working.\n"
    "This includes the keyboard class driver and the PS/2 port driver.\n"
    "\n";

/*++
 * @name RtlClipProcessMessage
 *
 * The RtlClipProcessMessage routine
 *
 * @param Command
 *        FILLMEIN
 *
 * @return None.
 *
 * @remarks Documentation for this routine needs to be completed.
 *
 *--*/
VOID RtlClipProcessMessage(PCHAR Command)
{
    WCHAR CurrentDirectory[MAX_PATH];
    WCHAR buf1[MAX_PATH];
    WCHAR buf2[MAX_PATH];
    UNICODE_STRING CurrentDirectoryString;
    CHAR CommandBuf[BUFFER_SIZE];

    //
    // Copy command line and break it to arguments
    //
    // if xargc = 3, then xargv[1], xargv[2], xargv[3] are available
    // xargv[1] is a command name, xargv[2] is the first parameter

    memset(CommandBuf, 0x00, BUFFER_SIZE);
    strncpy(CommandBuf, Command, strnlen(Command, BUFFER_SIZE));
    StringToArguments(CommandBuf);

    //
    // We'll call the handler for each command
    //
    if (!_strnicmp(Command, "exit", 4)) {
	//
	// Exit from shell
	//
	DeinitHeapMemory(hHeap);
	NtTerminateProcess(NtCurrentProcess(), 0);
    } else if (!_strnicmp(Command, "test", 4)) {
	UINT i = 0;

	RtlCliDisplayString("Args: %d\n", xargc);
	for (i = 1; i < xargc; i++) {
	    RtlCliDisplayString("Arg %d: %s\n", i, xargv[i]);
	}
    } else if (!_strnicmp(Command, "help", 4)) {
	RtlCliDisplayString("%s", helpstr);
    } else if (!_strnicmp(Command, "lm", 2)) {
	//
	// List Modules (!lm)
	//
	RtlCliListDrivers();
    } else if (!_strnicmp(Command, "lp", 2)) {
	//
	// List Processes (!lp)
	//
	RtlCliListProcesses();
    } else if (!_strnicmp(Command, "sysinfo", 7)) {
	//
	// Dump System Information (sysinfo)
	//
	RtlCliDumpSysInfo();
    } else if (!_strnicmp(Command, "cd", 2)) {
	//
	// Set the current directory
	//
	RtlCliSetCurrentDirectory(&Command[3]);
    } else if (!_strnicmp(Command, "locale", 6)) {
	//
	// Set the current directory
	//

	NtSetDefaultLocale(TRUE, 1049);
    } else if (!_strnicmp(Command, "pwd", 3)) {
	//
	// Get the current directory
	//
	RtlCliGetCurrentDirectory(CurrentDirectory);

	//
	// Display it
	//
	RtlInitUnicodeString(&CurrentDirectoryString, CurrentDirectory);
	RtlCliPrintString(&CurrentDirectoryString);

	RtlFreeUnicodeString(&CurrentDirectoryString);
    } else if (!_strnicmp(Command, "dir", 3)) {
	//
	// List the current directory
	//
	RtlCliListDirectory();
    } else if (!_strnicmp(Command, "devtree", 7)) {
	//
	// Dump hardware tree
	//
	RtlCliListHardwareTree();
    } else if (!_strnicmp(Command, "shutdown", 8)) {
	RtlCliShutdown();
    } else if (!_strnicmp(Command, "reboot", 6)) {
	RtlCliReboot();
    } else if (!_strnicmp(Command, "poweroff", 6)) {
	RtlCliPowerOff();
    } else if (!_strnicmp(Command, "vid", 6)) {
	UINT j;
	WCHAR i, w;
	UNICODE_STRING us;

	LARGE_INTEGER delay;
	memset(&delay, 0x00, sizeof(LARGE_INTEGER));
	delay.LowPart = 100000000;


	RtlInitUnicodeString(&us, L" ");

	//75x23
	RtlCliDisplayString("\nVid mode is 75x23\n\nCharacter test:");

	j = 0;
	for (w = L'A'; w < 0xFFFF; w++) {
	    j++;
	    NtDelayExecution(FALSE, &delay);
	    //w = i;
	    if (w != L'\n' && w != L'\r') {
		RtlCliPutChar(w);
	    } else {
		RtlCliPutChar(L' ');
	    }
	    if (j > 70) {
		j = 0;
		RtlCliPutChar(L'\n');
	    }
	}
    } else if (!_strnicmp(Command, "copy", 4)) {
	// Copy file
	if (xargc > 2) {
	    GetFullPath(xargv[2], buf1, sizeof(buf1), FALSE);
	    GetFullPath(xargv[3], buf2, sizeof(buf2), FALSE);
	    RtlCliDisplayString("\nCopy %S to %S\n", buf1, buf2);
	    if (FileExists(buf1)) {
		if (!NtFileCopyFile(buf1, buf2)) {
		    RtlCliDisplayString("Failed.\n");
		}
	    } else {
		RtlCliDisplayString("File does not exist.\n");
	    }
	} else {
	    RtlCliDisplayString("Not enough arguments.\n");
	}
    } else if (!_strnicmp(Command, "move", 4)) {
	// Move/rename file
	if (xargc > 2) {
	    GetFullPath(xargv[2], buf1, sizeof(buf1), FALSE);
	    GetFullPath(xargv[3], buf2, sizeof(buf2), FALSE);
	    RtlCliDisplayString("\nMove %S to %S\n", buf1, buf2);
	    if (FileExists(buf1)) {
		if (!NtFileMoveFile(buf1, buf2, FALSE)) {
		    RtlCliDisplayString("Failed.\n");
		}
	    } else {
		RtlCliDisplayString("File does not exist.\n");
	    }
	} else {
	    RtlCliDisplayString("Not enough arguments.\n");
	}
    } else if (!_strnicmp(Command, "del", 3)) {
	// Delete file
	if (xargc > 1) {
	    GetFullPath(xargv[2], buf1, sizeof(buf1), FALSE);
	    if (FileExists(buf1)) {
		RtlCliDisplayString("\nDelete %S\n", buf1);

		if (!NtFileDeleteFile(buf1)) {
		    RtlCliDisplayString("Failed.\n");
		}
	    } else {
		RtlCliDisplayString("File does not exist.\n");
	    }
	} else {
	    RtlCliDisplayString("Not enough arguments.\n");
	}
    } else if (!_strnicmp(Command, "md", 2)) {
	// Make directory
	if (xargc > 1) {
	    GetFullPath(xargv[2], buf1, sizeof(buf1), FALSE);

	    RtlCliDisplayString("\nCreate directory %S\n", buf1);

	    if (!NtFileCreateDirectory(buf1)) {
		RtlCliDisplayString("Failed.\n");
	    }
	} else {
	    RtlCliDisplayString("Not enough arguments.\n");
	}
    } else {
	//
	// Unknown command, try to find an executable and run it.
	// Executable name should be with an .exe extension.
	//

	WCHAR filename[MAX_PATH];
	ANSI_STRING as;
	UNICODE_STRING us;
	HANDLE hProcess;

	GetFullPath(xargv[1], filename, sizeof(filename), FALSE);

	if (FileExists(filename)) {
	    RtlInitAnsiString(&as, Command);
	    RtlAnsiStringToUnicodeString(&us, &as, TRUE);

	    NtClose(hKeyboard);
	    //RtlCliDisplayString("Keyboard is closed\n");

	    CreateNativeProcess(filename, us.Buffer, &hProcess);

	    RtlFreeAnsiString(&as);
	    RtlFreeUnicodeString(&us);

	    //RtlCliDisplayString("Waiting for process terminations\n");
	    NtWaitForSingleObject(hProcess, FALSE, NULL);

	    RtlCliOpenInputDevice(&hKeyboard, KeyboardType);
	    //RtlCliDisplayString("Keyboard restored\n");
	} else {
	    RtlCliDisplayString("%s not recognized\n", Command);
	}
    }
}

/*++
 * @name RtlClipDisplayPrompt
 *
 * The RtlClipDisplayPrompt routine
 *
 * @param None.
 *
 * @return None.
 *
 * @remarks Documentation for this routine needs to be completed.
 *
 *--*/
VOID RtlClipDisplayPrompt(VOID)
{
    WCHAR CurrentDirectory[MAX_PATH];
    ULONG DirSize;
    UNICODE_STRING DirString;

    //
    // Get the current directory
    //
    DirSize = RtlCliGetCurrentDirectory(CurrentDirectory) / sizeof(WCHAR);

    //
    // Display it
    //
    CurrentDirectory[DirSize] = L'>';
    CurrentDirectory[DirSize + 1] = UNICODE_NULL;
    RtlInitUnicodeString(&DirString, CurrentDirectory);
    RtlCliPrintString(&DirString);
}

/*++
 * @name main
 *
 * The main routine
 *
 * @param argc
 *        FILLMEIN
 *
 * @param argv[]
 *        FILLMEIN
 *
 * @param envp[]
 *        FILLMEIN
 *
 * @param DebugFlag
 *        FILLMEIN
 *
 * @return NTSTATUS
 *
 * @remarks Documentation for this routine needs to be completed.
 *
 *--*/
NTAPI VOID NtProcessStartup(PPEB Peb)
{
    NTSTATUS Status;
    PCHAR Command;

    hHeap = InitHeapMemory();
    hKey = NULL;

    //
    // Show banner
    //
    RtlCliDisplayString(NTCMD_BANNER);
    RtlCliDisplayString("Type \"help\".\n\n");

    //
    // Setup keyboard input
    //
    Status = RtlCliOpenInputDevice(&hKeyboard, KeyboardType);

    //
    // Show initial prompt
    //
    RtlClipDisplayPrompt();

    //
    // Wait for a new line
    //
    while (TRUE) {
	//
	// Get the line that was entered and display a new line
	//
	Command = RtlCliGetLine(hKeyboard);
	RtlCliDisplayString("\n");

	//
	// Make sure there's actually a command
	//
	if (Command && *Command) {
	    //
	    // Process the command and do a new line again.
	    //
	    RtlClipProcessMessage(Command);
	    RtlCliDisplayString("\n");
	}
	//
	// Display the prompt, and restart the loop
	//
	RtlClipDisplayPrompt();
	continue;
    }

    DeinitHeapMemory(hHeap);
    NtTerminateProcess(NtCurrentProcess(), 0);
}
