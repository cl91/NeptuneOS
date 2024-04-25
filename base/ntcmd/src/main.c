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

#define NTCMD_BANNER "Neptune OS Native Command Prompt [Version " VER_PRODUCTVERSION_STRING "]\n"

PCSTR helpstr =
    "\n"
    "dir      - Show directory contents  pwd      - Print working directory\n"
    "dump X   - Show hexdump for file X  edlin X  - Edit lines for file X\n"
    "cd X     - Change directory to X    md X     - Make directory X\n"
    "copy X Y - Copy file X to Y         move X Y - Move file X to Y\n"
    "del X    - Delete file X            sync     - Synchronize file systems\n"
    "mount A  - Mount drive A            umount A - Unmount drive A\n"
    "lm       - List modules             lp       - List processes\n"
    "devtree  - Dump device tree         sysinfo  - Dump system information\n"
    "exit     - Exit shell               shutdown - Shutdown system\n"
    "poweroff - Power off system         reboot   - Reboot system\n"
    "\n"
    "If a command is not in the list, it is treated as an executable name.\n"
    "\n"
    "Note: to demonstrate the functionalities of the cache manager, write-back\n"
    "caching is enabled for the floppy drive. You MUST run `umount A' before\n"
    "removing a disk, or risk data corruption.\n"
    "\n";

#define COMPARE_CMD(Command, String) _strnicmp(Command, String, sizeof(String)-1)

#define CMD_BUFSIZE	1024
#define MAX_ARGS	16

/*++
 * @name RtlClipProcessMessage
 *
 * Process the given user command string and execute the command.
 *
 * @param Command
 *        Command to be processed.
 *
 * @return TRUE if processing should continue. FALSE if user requested to exit
 *         the shell.
 *
 *--*/
BOOLEAN RtlClipProcessMessage(PCHAR Command)
{
    WCHAR CurrentDirectory[MAX_PATH];
    WCHAR buf1[MAX_PATH];
    WCHAR buf2[MAX_PATH];
    UNICODE_STRING CurrentDirectoryString;
    CHAR CommandBuf[CMD_BUFSIZE];
    PCHAR xargv[MAX_ARGS];

    //
    // Copy command line and break it down to arguments
    //
    // if xargc = 3, then xargv[0], xargv[1], xargv[2] are available
    // xargv[0] is a command name, xargv[1] is the first parameter, etc.
    memset(CommandBuf, 0x00, CMD_BUFSIZE);
    strncpy(CommandBuf, Command, strnlen(Command, CMD_BUFSIZE));
    ULONG xargc = StringToArguments(CommandBuf, CMD_BUFSIZE, MAX_ARGS, xargv);

    //
    // We'll call the handler for each command
    //
    if (!COMPARE_CMD(Command, "exit")) {
	//
	// Exit from the shell
	//
	return FALSE;
    } else if (!COMPARE_CMD(Command, "test")) {
	//
	// Test the command line parsing routine
	//
	UINT i = 0;
	RtlCliDisplayString("Args: %d\n", xargc);
	for (i = 0; i < xargc; i++) {
	    RtlCliDisplayString("Arg %d: %s\n", i, xargv[i]);
	}
    } else if (!COMPARE_CMD(Command, "help")) {
	//
	// Display help
	//
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
	if (xargc == 2) {
	    NTSTATUS Status = RtlCliSetCurrentDirectory(xargv[1]);
	    if (!NT_SUCCESS(Status)) {
		RtlCliDisplayString("cd: invalid directory (error 0x%08x)\n",
				    Status);
	    }
	} else if (xargc > 2) {
	    RtlCliDisplayString("Too many arguments.\n");
	} else {
	    RtlCliDisplayString("Not enough arguments.\n");
	}
    } else if (!COMPARE_CMD(Command, "locale")) {
	//
	// Set the default locale
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

	//75x23
	RtlCliDisplayString("\nVid mode is 75x23\n\nCharacter test:\n");

	j = 0;
	for (w = L'A'; w < 0xFF; w++) {
	    j++;
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
	if (xargc == 3) {
	    GetFullPath(xargv[1], buf1, sizeof(buf1), FALSE);
	    GetFullPath(xargv[2], buf2, sizeof(buf2), FALSE);
	    RtlCliDisplayString("\nCopy %S to %S\n", buf1, buf2);
	    if (FileExists(buf1)) {
		if (!NtFileCopyFile(buf1, buf2)) {
		    RtlCliDisplayString("Failed.\n");
		}
	    } else {
		RtlCliDisplayString("File does not exist.\n");
	    }
	} else if (xargc > 3) {
	    RtlCliDisplayString("Too many arguments.\n");
	} else {
	    RtlCliDisplayString("Not enough arguments.\n");
	}
    } else if (!COMPARE_CMD(Command, "move")) {
	// Move/rename file
	if (xargc == 3) {
	    GetFullPath(xargv[1], buf1, sizeof(buf1), FALSE);
	    GetFullPath(xargv[2], buf2, sizeof(buf2), FALSE);
	    RtlCliDisplayString("\nMove %S to %S\n", buf1, buf2);
	    if (FileExists(buf1)) {
		if (!NtFileMoveFile(buf1, buf2, FALSE)) {
		    RtlCliDisplayString("Failed.\n");
		}
	    } else {
		RtlCliDisplayString("File does not exist.\n");
	    }
	} else if (xargc > 3) {
	    RtlCliDisplayString("Too many arguments.\n");
	} else {
	    RtlCliDisplayString("Not enough arguments.\n");
	}
    } else if (!COMPARE_CMD(Command, "del")) {
	// Delete file
	if (xargc == 2) {
	    GetFullPath(xargv[1], buf1, sizeof(buf1), FALSE);
	    if (FileExists(buf1)) {
		RtlCliDisplayString("\nDelete %S\n", buf1);

		if (!NtFileDeleteFile(buf1)) {
		    RtlCliDisplayString("Failed.\n");
		}
	    } else {
		RtlCliDisplayString("File does not exist.\n");
	    }
	} else if (xargc > 2) {
	    RtlCliDisplayString("Too many arguments.\n");
	} else {
	    RtlCliDisplayString("Not enough arguments.\n");
	}
    } else if (!COMPARE_CMD(Command, "md")) {
	// Make directory
	if (xargc == 2) {
	    GetFullPath(xargv[2], buf1, sizeof(buf1), FALSE);
	    RtlCliDisplayString("\nCreate directory %S\n", buf1);
	    if (!NtFileCreateDirectory(buf1)) {
		RtlCliDisplayString("Failed.\n");
	    }
	} else if (xargc > 2) {
	    RtlCliDisplayString("Too many arguments.\n");
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
	    CreateNativeProcess(filename, us.Buffer, &hProcess);
	    RtlFreeAnsiString(&as);
	    RtlFreeUnicodeString(&us);

	    NtWaitForSingleObject(hProcess, FALSE, NULL);
	    RtlCliOpenInputDevice(&hKeyboard, KeyboardType);
	} else {
	    RtlCliDisplayString("%s not recognized.\n", Command);
	}
    }
    return TRUE;
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
 * @name NtProcessStartup
 *
 * This is the entry point for the Native Command Prompt.
 *
 *--*/
NTAPI VOID NtProcessStartup(PPEB Peb)
{
    PCHAR Command;

    HANDLE hHeap = InitHeapMemory();

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
	    if (!RtlClipProcessMessage(Command)) {
		break;
	    }
	    RtlCliDisplayString("\n");
	}
	//
	// Display the prompt, and restart the loop
	//
	RtlClipDisplayPrompt();
    }

end:
    DeinitHeapMemory(hHeap);
    NtTerminateProcess(NtCurrentProcess(), 0);
}
