/*++

Copyright (c) Alex Ionescu.  All rights reserved.
Copyright (c) 2011 amdf.

Module Name:

    main.c

Abstract:

    The Native Command Line Interface is the command shell for Neptune OS.
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
    "dir      - Show directory contents  pwd      - Print working directory\n"
    "dump X   - Show hexdump for file X  edlin X  - Edit lines for file X\n"
    "cd X     - Change directory to X    md X     - Make directory X\n"
    "copy X Y - Copy file X to Y         move X Y - Move file X to Y\n"
    "del X    - Delete file X            sync     - Synchronize file systems\n"
    "devtree  - Dump device tree         sysinfo  - Dump system information\n"
    "lm       - List modules             lp       - List processes\n"
    "test     - Test argument parsing    vid      - Test screen output\n"
    "exit     - Exit shell               poweroff - Power off system\n"
    "shutdown - Shutdown system          reboot   - Reboot system\n"
    "\n"
    "If a command is not in the list, it is treated as an executable name.\n"
    "\n"
    "Note: to demonstrate the functions of the cache manager, write-back\n"
    "caching is enabled for the floppy drive. You MUST run `sync' before\n"
    "removing a disk, or risk data corruption.\n"
    "\n";

#define COMPARE_CMD(Command, String) _strnicmp(Command, String, sizeof(String)-1)

/*++
 * @name RtlClipProcessMessage
 *
 * The RtlClipProcessMessage routine
 *
 * @param Command
 *        Command to be processed.
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
    // Copy command line and break it down to arguments
    //
    // if xargc = 3, then xargv[1], xargv[2], xargv[3] are available
    // xargv[1] is a command name, xargv[2] is the first parameter

    memset(CommandBuf, 0x00, BUFFER_SIZE);
    strncpy(CommandBuf, Command, strnlen(Command, BUFFER_SIZE));
    StringToArguments(CommandBuf);

    //
    // We'll call the handler for each command
    //
    if (!COMPARE_CMD(Command, "exit")) {
	//
	// Exit from the shell
	//
	DeinitHeapMemory(hHeap);
	NtTerminateProcess(NtCurrentProcess(), 0);
    } else if (!COMPARE_CMD(Command, "test")) {
	UINT i = 0;

	RtlCliDisplayString("Args: %d\n", xargc);
	for (i = 1; i < xargc; i++) {
	    RtlCliDisplayString("Arg %d: %s\n", i, xargv[i]);
	}
    } else if (!COMPARE_CMD(Command, "help")) {
	RtlCliDisplayString("%s", helpstr);
    } else if (!COMPARE_CMD(Command, "lm")) {
	//
	// List Modules (!lm)
	//
	RtlCliListDrivers();
    } else if (!COMPARE_CMD(Command, "lp")) {
	//
	// List Processes (!lp)
	//
	RtlCliListProcesses();
    } else if (!COMPARE_CMD(Command, "sysinfo")) {
	//
	// Dump System Information (sysinfo)
	//
	RtlCliDumpSysInfo();
    } else if (!COMPARE_CMD(Command, "cd")) {
	//
	// Set the current directory
	//
	RtlCliSetCurrentDirectory(&Command[3]);
    } else if (!COMPARE_CMD(Command, "locale")) {
	//
	// Set the current directory
	//

	NtSetDefaultLocale(TRUE, 1049);
    } else if (!COMPARE_CMD(Command, "pwd")) {
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
    } else if (!COMPARE_CMD(Command, "dir")) {
	//
	// List the current directory
	//
	RtlCliListDirectory();
    } else if (!COMPARE_CMD(Command, "devtree")) {
	//
	// Dump hardware tree
	//
	RtlCliListHardwareTree();
    } else if (!COMPARE_CMD(Command, "shutdown")) {
	RtlCliShutdown();
    } else if (!COMPARE_CMD(Command, "reboot")) {
	RtlCliReboot();
    } else if (!COMPARE_CMD(Command, "poweroff")) {
	RtlCliPowerOff();
    } else if (!COMPARE_CMD(Command, "vid")) {
	UINT j;
	WCHAR w;
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
    } else if (!COMPARE_CMD(Command, "copy")) {
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
    } else if (!COMPARE_CMD(Command, "move")) {
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
    } else if (!COMPARE_CMD(Command, "del")) {
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
    } else if (!COMPARE_CMD(Command, "md")) {
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
    NTSTATUS Status = RtlCliOpenInputDevice(&hKeyboard, KeyboardType);
    if (!NT_SUCCESS(Status)) {
	RtlCliDisplayString("Unable to open keyboard. Error 0x%.8x\n", Status);
	goto end;
    }

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

end:
    DeinitHeapMemory(hHeap);
    NtTerminateProcess(NtCurrentProcess(), 0);
}
