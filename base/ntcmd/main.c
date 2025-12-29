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
#include "ntcmd.h"
#include "ntexapi.h"
#include "ntstatus.h"
#include "string.h"

HANDLE hKeyboard;
ULONG ConsoleMaxRows = 24;
ULONG ConsoleMaxColumns = 80;

#define NTCMD_BANNER "Neptune OS Native Command Prompt [Version " VER_PRODUCTVERSION_STRING "]\n"

PCSTR HELPSTR =
    "\n"
    "dir      - Show directory contents    pwd      - Print working directory\n"
    "dump X   - Show hexdump for file X    edlin X  - Edit lines for file X\n"
    "cd X     - Change directory to X      md X     - Make directory X\n"
    "copy X Y - Copy file X to Y           move X Y - Move file X to Y\n"
    "del X    - Delete file or dir X       sync A   - Flush caches for drive A\n"
    "mount A  - Mount drive A              umount A - Unmount drive A\n"
    "lm       - List driver modules        lp       - List processes\n"
    "devtree  - Dump device tree           sysinfo  - Dump system information\n"
    "poweroff - Power off system           reboot   - Reboot system\n"
    "\n"
    "If a command is not in the list, it is treated as an executable name.\n"
    "\n"
    "Note: to demonstrate the functionalities of the cache manager, write-back\n"
    "caching is enabled for the floppy drive. You MUST run `umount A' before\n"
    "removing a disk, or risk data corruption.\n"
    "\n";

#define COMPARE_CMD(Command, String) (!_strnicmp(Command, String, sizeof(String)-1))

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
    WCHAR buf1[MAX_PATH];
    WCHAR buf2[MAX_PATH];
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
    if (COMPARE_CMD(Command, "exit")) {
	//
	// Exit from the shell
	//
	return FALSE;
    } else if (COMPARE_CMD(Command, "test")) {
	//
	// Test the command line parsing routine
	//
	UINT i = 0;
	RtlCliDisplayString("Args: %d\n", xargc);
	for (i = 0; i < xargc; i++) {
	    RtlCliDisplayString("Arg %d: %s\n", i, xargv[i]);
	}
    } else if (COMPARE_CMD(Command, "help")) {
	//
	// Display help
	//
	RtlCliDisplayString("%s", HELPSTR);
    } else if (COMPARE_CMD(Command, "lm")) {
	//
	// List Modules (!lm)
	//
	RtlCliListDrivers();
    } else if (COMPARE_CMD(Command, "lp")) {
	//
	// List Processes (!lp)
	//
	RtlCliListProcesses();
    } else if (COMPARE_CMD(Command, "sysinfo")) {
	//
	// Dump System Information (sysinfo)
	//
	RtlCliDumpSysInfo();
    } else if (COMPARE_CMD(Command, "cd")) {
	//
	// Set the current directory
	//
	if (xargc == 2) {
	    NTSTATUS Status = RtlCliSetCurrentDirectory(xargv[1]);
	    if (!NT_SUCCESS(Status)) {
		RtlCliDisplayString("cd: %s\n", RtlCliStatusToErrorMessage(Status));
	    }
	} else if (xargc > 2) {
	    RtlCliDisplayString("Too many arguments.\n");
	} else {
	    RtlCliDisplayString("Not enough arguments.\n");
	}
    } else if (COMPARE_CMD(Command, "locale")) {
	//
	// Set the default locale
	//
	NtSetDefaultLocale(TRUE, 1049);
    } else if (COMPARE_CMD(Command, "pwd")) {
	//
	// Display the current directory
	//
	WCHAR CurrentDirectory[MAX_PATH];
	RtlCliGetCurrentDirectory(CurrentDirectory);
	RtlCliDisplayString("%ws\n", CurrentDirectory);
    } else if (COMPARE_CMD(Command, "dir")) {
	//
	// List the current directory
	//
	RtlCliListDirectory();
    } else if (COMPARE_CMD(Command, "devtree")) {
	//
	// Dump hardware tree
	//
	RtlCliListHardwareTree();
    } else if (COMPARE_CMD(Command, "dump")) {
	//
	// Dump the file content
	//
	if (xargc == 2) {
	    NTSTATUS Status = GetFullPath(xargv[1], buf1, sizeof(buf1), FALSE);
	    if (!NT_SUCCESS(Status)) {
		RtlCliDisplayString("dump: %s\n", RtlCliStatusToErrorMessage(Status));
	    }
	    Status = RtlCliDumpFile(buf1);
	    if (!NT_SUCCESS(Status)) {
		RtlCliDisplayString("dump: %s\n", RtlCliStatusToErrorMessage(Status));
	    }
	} else if (xargc > 2) {
	    RtlCliDisplayString("Too many arguments.\n");
	} else {
	    RtlCliDisplayString("Not enough arguments.\n");
	}
    } else if (COMPARE_CMD(Command, "edlin")) {
	//
	// Open line editor
	//
	if (xargc == 2) {
	    RtlCliEditLineFile(xargv[1]);
	} else if (xargc > 2) {
	    RtlCliDisplayString("Too many arguments.\n");
	} else {
	    RtlCliDisplayString("Usage: edlin <filename>. Commands:\n");
	    RtlCliDisplayString("  n          – print line n\n");
	    RtlCliDisplayString("  n text...  – replace line n\n");
	    RtlCliDisplayString("  p          – print all lines\n");
	    RtlCliDisplayString("  s          – save\n");
	    RtlCliDisplayString("  q          – quit\n");
	}

    } else if (COMPARE_CMD(Command, "shutdown")) {
	RtlCliShutdown();
    } else if (COMPARE_CMD(Command, "reboot")) {
	RtlCliReboot();
    } else if (COMPARE_CMD(Command, "poweroff")) {
	RtlCliPowerOff();
    } else if (COMPARE_CMD(Command, "vid")) {
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
    } else if (COMPARE_CMD(Command, "copy")) {
	// Copy file
	if (xargc == 3) {
	    NTSTATUS Status =  GetFullPath(xargv[1], buf1, sizeof(buf1), FALSE);
	    if (!NT_SUCCESS(Status)) {
		RtlCliDisplayString("copy: %s\n", RtlCliStatusToErrorMessage(Status));
	    }
	    Status = GetFullPath(xargv[2], buf2, sizeof(buf2), FALSE);
	    if (!NT_SUCCESS(Status)) {
		RtlCliDisplayString("copy: %s\n", RtlCliStatusToErrorMessage(Status));
	    }
	    if (FileExists(buf1)) {
		Status = CopyFile(buf1, buf2);
		if (!NT_SUCCESS(Status)) {
		    RtlCliDisplayString("copy: %s\n", RtlCliStatusToErrorMessage(Status));
		}
	    } else {
		RtlCliDisplayString("File %ws does not exist.\n", buf1);
	    }
	} else if (xargc > 3) {
	    RtlCliDisplayString("Too many arguments.\n");
	} else {
	    RtlCliDisplayString("Not enough arguments.\n");
	}
    } else if (COMPARE_CMD(Command, "move")) {
	// Move/rename file
	if (xargc == 3) {
	    NTSTATUS Status = GetFullPath(xargv[1], buf1, sizeof(buf1), FALSE);
	    if (!NT_SUCCESS(Status)) {
		RtlCliDisplayString("move: %s\n", RtlCliStatusToErrorMessage(Status));
	    }
	    Status = GetFullPath(xargv[2], buf2, sizeof(buf2), FALSE);
	    if (!NT_SUCCESS(Status)) {
		RtlCliDisplayString("move: %s\n", RtlCliStatusToErrorMessage(Status));
	    }
	    if (FileExists(buf1)) {
		Status = MoveFile(buf1, buf2, FALSE);
		if (!NT_SUCCESS(Status)) {
		    RtlCliDisplayString("move: %s\n", RtlCliStatusToErrorMessage(Status));
		}
	    } else {
		RtlCliDisplayString("File %ws does not exist.\n", buf1);
	    }
	} else if (xargc > 3) {
	    RtlCliDisplayString("Too many arguments.\n");
	} else {
	    RtlCliDisplayString("Not enough arguments.\n");
	}
    } else if (COMPARE_CMD(Command, "del")) {
	// Delete file
	if (xargc == 2) {
	    NTSTATUS Status = GetFullPath(xargv[1], buf1, sizeof(buf1), FALSE);
	    if (!NT_SUCCESS(Status)) {
		RtlCliDisplayString("del: %s\n", RtlCliStatusToErrorMessage(Status));
	    }
	    if (FileExists(buf1)) {
		Status = DeleteFile(buf1);
		if (!NT_SUCCESS(Status)) {
		    RtlCliDisplayString("del: %s\n", RtlCliStatusToErrorMessage(Status));
		}
	    } else {
		RtlCliDisplayString("File %ws does not exist.\n", buf1);
	    }
	} else if (xargc > 2) {
	    RtlCliDisplayString("Too many arguments.\n");
	} else {
	    RtlCliDisplayString("Not enough arguments.\n");
	}
    } else if (COMPARE_CMD(Command, "md")) {
	// Make directory
	if (xargc == 2) {
	    NTSTATUS Status = GetFullPath(xargv[1], buf1, sizeof(buf1), FALSE);
	    if (!NT_SUCCESS(Status)) {
		RtlCliDisplayString("md: %s\n", RtlCliStatusToErrorMessage(Status));
	    }
	    Status = CreateDirectory(buf1);
	    if (!NT_SUCCESS(Status)) {
		RtlCliDisplayString("md: %s\n", RtlCliStatusToErrorMessage(Status));
	    }
	} else if (xargc > 2) {
	    RtlCliDisplayString("Too many arguments.\n");
	} else {
	    RtlCliDisplayString("Not enough arguments.\n");
	}
    } else if (COMPARE_CMD(Command, "mount")) {
	// Mount the volume
	if (xargc == 2) {
	    NTSTATUS Status = MountVolume(xargv[1]);
	    if (!NT_SUCCESS(Status)) {
		RtlCliDisplayString("mount: %s\n", RtlCliStatusToErrorMessage(Status));
	    }
	} else if (xargc > 2) {
	    RtlCliDisplayString("Too many arguments.\n");
	} else {
	    RtlCliDisplayString("Not enough arguments.\n");
	}
    } else if (COMPARE_CMD(Command, "sync")) {
	// Flush buffers
	if (xargc == 2) {
	    NTSTATUS Status = FlushBuffers(xargv[1]);
	    if (!NT_SUCCESS(Status)) {
		RtlCliDisplayString("sync: %s\n", RtlCliStatusToErrorMessage(Status));
	    }
	} else if (xargc > 2) {
	    RtlCliDisplayString("Too many arguments.\n");
	} else {
	    RtlCliDisplayString("Not enough arguments.\n");
	}
    } else if (COMPARE_CMD(Command, "umount")) {
	// Dismount the volume
	if (xargc == 2) {
	    NTSTATUS Status = DismountVolume(xargv[1]);
	    if (!NT_SUCCESS(Status)) {
		RtlCliDisplayString("umount: %s\n", RtlCliStatusToErrorMessage(Status));
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
	WCHAR FileName[MAX_PATH] = {};
	ANSI_STRING AnsiString;
	UNICODE_STRING UnicodeString;
	HANDLE Process;

	NTSTATUS Status = GetFullPath(xargv[0], FileName, sizeof(FileName), FALSE);
	if (!NT_SUCCESS(Status)) {
	    RtlCliDisplayString("%s not recognized: %s\n", Command,
				RtlCliStatusToErrorMessage(Status));
	}
	if (!FileExists(FileName)) {
	    if (!strstr(xargv[0], ".exe")) {
		/* Try adding a .exe extension to the file. */
		wcscat_s(FileName, MAX_PATH, L".exe");
		if (FileExists(FileName)) {
		    goto ok;
		}
	    }
	    RtlCliDisplayString("%s not recognized.\n", Command);
	    return TRUE;
	}

    ok:
	RtlInitAnsiString(&AnsiString, Command);
	RtlAnsiStringToUnicodeString(&UnicodeString, &AnsiString, TRUE);

	NtClose(hKeyboard);
	CreateNativeProcess(FileName, UnicodeString.Buffer, &Process);
	RtlFreeUnicodeString(&UnicodeString);

	NtWaitForSingleObject(Process, FALSE, NULL);
	NtClose(Process);
	RtlCliOpenInputDevice(&hKeyboard, KeyboardType);
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
    NtDisplayString(&DirString);
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
    // Query the system to get the console size
    //
    SYSTEM_BOOT_CONSOLE_INFORMATION ConsoleInfo = {};
    ULONG BufferSize = sizeof(ConsoleInfo);
    NTSTATUS Status = NtQuerySystemInformation(SystemBootConsoleInformation,
					       &ConsoleInfo, BufferSize, &BufferSize);
    assert(!NT_SUCCESS(Status) || (ConsoleInfo.NumberOfRows && ConsoleInfo.NumberOfColumns));
    if (NT_SUCCESS(Status) && ConsoleInfo.NumberOfRows && ConsoleInfo.NumberOfColumns) {
	ConsoleMaxRows = ConsoleInfo.NumberOfRows;
	ConsoleMaxColumns = ConsoleInfo.NumberOfColumns;
    }

    //
    // Setup keyboard input
    //
    Status = RtlCliOpenInputDevice(&hKeyboard, KeyboardType);
    if (!NT_SUCCESS(Status)) {
	RtlCliDisplayString("Unable to open keyboard. Error 0x%.8x\n", Status);
	goto end;
    }

    //
    // Switch current directory to the root of C: drive. If that fails,
    // try the A: drive.
    //
    Status = RtlCliSetCurrentDirectory("C:\\");
    if (!NT_SUCCESS(Status)) {
	RtlCliSetCurrentDirectory("A:\\");
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
	    // Process the command
	    //
	    if (!RtlClipProcessMessage(Command)) {
		break;
	    }
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
