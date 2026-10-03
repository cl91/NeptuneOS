/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            dll/win32/kernel32/client/except.c
 * PURPOSE:         Exception functions
 * PROGRAMMER:      Ariadne (ariadne@xs4all.nl)
 *                  Modified from WINE [ Onno Hovers, (onno@stack.urc.tue.nl) ]
 * UPDATE HISTORY:
 *                  Created 01/11/98
 */

/* INCLUDES *******************************************************************/

#include <k32.h>
#include <strsafe.h>

/*
 * Private helper function to lookup the module name from a given address.
 * The address can point to anywhere within the module.
 */
static const char *ModuleNameFromAddr(const void *Addr, void **ModuleStartAddr,
				      char *pSz, size_t nChars, char **ModuleName)
{
    MEMORY_BASIC_INFORMATION Info;

    if ((nChars > MAXDWORD) || (VirtualQuery(Addr, &Info, sizeof(Info)) != sizeof(Info)) ||
	!GetModuleFileNameA((HMODULE)Info.AllocationBase, pSz, (DWORD)nChars)) {
	pSz[0] = '\0';
	*ModuleName = pSz;
	*ModuleStartAddr = 0;
    } else {
	char *Str1 = strrchr(pSz, '\\'), *Str2 = strrchr(pSz, '/');
	if (Str2 && !Str1)
	    Str1 = Str2;
	else if (Str1 && Str2 && Str1 < Str2)
	    Str1 = Str2;

	if (!Str1)
	    Str1 = pSz;
	else
	    Str1++;

	*ModuleName = Str1;
	*ModuleStartAddr = (void *)Info.AllocationBase;
    }
    return pSz;
}

static VOID DumpContext(PCONTEXT Ctx)
{
#ifdef _M_IX86
    /*
     * Print out the CPU registers
     */
    DbgPrint("EIP %x\n", Ctx->Eip);
    DbgPrint("FS %x GS %x\n", Ctx->FsBase, Ctx->GsBase);
    DbgPrint("EAX: %.8x   EBX: %.8x   ECX: %.8x\n", Ctx->Eax, Ctx->Ebx, Ctx->Ecx);
    DbgPrint("EDX: %.8x   EBP: %.8x   ESI: %.8x   ESP: %.8x\n", Ctx->Edx, Ctx->Ebp, Ctx->Esi,
	     Ctx->Esp);
    DbgPrint("EDI: %.8x   EFLAGS: %.8x\n", Ctx->Edi, Ctx->EFlags);
#elif defined(_M_AMD64)
    DbgPrint("RIP %I64x\n", Ctx->Rip);
    DbgPrint("FS %llx GS %llx\n", Ctx->FsBase, Ctx->GsBase);
    DbgPrint("RAX: %I64x   RBX: %I64x   RCX: %I64x RDI: %I64x\n", Ctx->Rax, Ctx->Rbx,
	     Ctx->Rcx, Ctx->Rdi);
    DbgPrint("RDX: %I64x   RBP: %I64x   RSI: %I64x   RSP: %I64x\n", Ctx->Rdx, Ctx->Rbp,
	     Ctx->Rsi, Ctx->Rsp);
    DbgPrint("R8: %I64x   R9: %I64x   R10: %I64x   R11: %I64x\n", Ctx->R8, Ctx->R9, Ctx->R10,
	     Ctx->R11);
    DbgPrint("R12: %I64x   R13: %I64x   R14: %I64x   R15: %I64x\n", Ctx->R12, Ctx->R13,
	     Ctx->R14, Ctx->R15);
    DbgPrint("EFLAGS: %.8x\n", Ctx->EFlags);
#elif defined(_M_ARM)
    DbgPrint("CTX:  %08lx   LR:  %08lx   SP:  %08lx\n", Ctx->Ctx, Ctx->Lr, Ctx->Sp);
    DbgPrint("R0:  %08lx   R1:  %08lx   R2:  %08lx   R3:  %08lx\n", Ctx->R0, Ctx->R1,
	     Ctx->R2, Ctx->R3);
    DbgPrint("R4:  %08lx   R5:  %08lx   R6:  %08lx   R7:  %08lx\n", Ctx->R4, Ctx->R5,
	     Ctx->R6, Ctx->R7);
    DbgPrint("R8:  %08lx   R9:  %08lx   R10: %08lx   R11: %08lx\n", Ctx->R8, Ctx->R9,
	     Ctx->R10, Ctx->R11);
    DbgPrint("R12: %08lx   CPSR: %08lx  FPSCR: %08lx\n", Ctx->R12, Ctx->Cpsr, Ctx->Fpscr);
#else
#error "Unknown architecture"
#endif
}

static VOID PrintStackTrace(IN PEXCEPTION_POINTERS ExceptionInfo)
{
    PVOID StartAddr;
    CHAR szMod[128] = "", *szModFile;
    PEXCEPTION_RECORD ExceptionRecord = ExceptionInfo->ExceptionRecord;
    PCONTEXT ContextRecord = ExceptionInfo->ContextRecord;

    /* Print a stack trace */
    DbgPrint("Unhandled exception\n");
    DbgPrint("ExceptionCode:    %8x\n", ExceptionRecord->ExceptionCode);

    if (ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION &&
	ExceptionRecord->NumberParameters == 2) {
	DbgPrint("Faulting Address: %p\n",
		 (PVOID)ExceptionRecord->ExceptionInformation[1]);
    }

    /* Trace the wine special error and show the modulename and functionname */
    if (ExceptionRecord->ExceptionCode == 0x80000100 /* EXCEPTION_WINE_STUB */ &&
	ExceptionRecord->NumberParameters == 2) {
	DbgPrint("Missing function: %s!%s\n",
		 (PSZ)ExceptionRecord->ExceptionInformation[0],
		 (PSZ)ExceptionRecord->ExceptionInformation[1]);
    }

    DumpContext(ContextRecord);
    ModuleNameFromAddr(ExceptionRecord->ExceptionAddress, &StartAddr, szMod,
		       sizeof(szMod), &szModFile);
    DbgPrint("Address:\n<%s:%zx> (%s@%p)\n", szModFile,
	     (ULONG_PTR)ExceptionRecord->ExceptionAddress - (ULONG_PTR)StartAddr, szMod,
	     StartAddr);
#ifdef _M_IX86
    DbgPrint("Frames:\n");

    __try {
	UINT i;
	PULONG Frame = (PULONG)ContextRecord->Ebp;

	for (i = 0; Frame[1] != 0 && Frame[1] != 0xdeadbeef && i < 128; i++) {
	    if (IsBadReadPtr((PVOID)Frame[1], 4)) {
		DbgPrint("<%s:%x>\n", "[invalid address]", Frame[1]);
	    } else {
		ModuleNameFromAddr((const void *)Frame[1], &StartAddr, szMod,
				   sizeof(szMod), &szModFile);
		DbgPrint("<%s:%x> (%s@%p)\n", szModFile,
			 (ULONG_PTR)Frame[1] - (ULONG_PTR)StartAddr, szMod, StartAddr);
	    }

	    if (IsBadReadPtr((PVOID)Frame[0], sizeof(*Frame) * 2))
		break;

	    Frame = (PULONG)Frame[0];
	}
    } __except (EXCEPTION_EXECUTE_HANDLER) {
	DbgPrint("<error dumping stack trace: 0x%lx>\n", GetExceptionCode());
    }
#endif
}

/* GLOBALS ********************************************************************/

LPTOP_LEVEL_EXCEPTION_FILTER GlobalTopLevelExceptionFilter;
DWORD g_dwLastErrorToBreakOn;

/* FUNCTIONS ******************************************************************/

WINAPI LONG BasepCheckForReadOnlyResource(IN PVOID Ptr)
{
    PVOID Data;
    ULONG Size, OldProtect;
    SIZE_T Size2;
    MEMORY_BASIC_INFORMATION Info;
    NTSTATUS Status;
    LONG Ret = EXCEPTION_CONTINUE_SEARCH;

    /* Check if it was an attempt to write to a read-only image section! */
    Status = NtQueryVirtualMemory(NtCurrentProcess(), Ptr, MemoryBasicInformation, &Info,
				  sizeof(Info), NULL);
    if (NT_SUCCESS(Status) && Info.Protect == PAGE_READONLY && Info.Type == MEM_IMAGE) {
	/* Attempt to treat it as a resource section. We need to
	   use SEH here because we don't know if it's actually a
	   resource mapping */
	__try {
	    Data = RtlImageDirectoryEntryToData(Info.AllocationBase, TRUE,
						IMAGE_DIRECTORY_ENTRY_RESOURCE, &Size);

	    if (Data != NULL && (ULONG_PTR)Ptr >= (ULONG_PTR)Data &&
		(ULONG_PTR)Ptr < (ULONG_PTR)Data + Size) {
		/* The user tried to write into the resources. Make the page
		   writable... */
		Size2 = 1;
		Status = NtProtectVirtualMemory(NtCurrentProcess(), &Ptr, &Size2,
						PAGE_READWRITE, &OldProtect);
		if (NT_SUCCESS(Status)) {
		    Ret = EXCEPTION_CONTINUE_EXECUTION;
		}
	    }
	} __except (EXCEPTION_EXECUTE_HANDLER) {
	}
    }

    return Ret;
}

WINAPI UINT GetErrorMode(VOID)
{
    NTSTATUS Status;
    UINT ErrMode;

    /* Query the current setting */
    Status = NtQueryInformationProcess(NtCurrentProcess(), ProcessDefaultHardErrorMode,
				       &ErrMode, sizeof(ErrMode), NULL);
    if (!NT_SUCCESS(Status)) {
	/* Fail if we couldn't query */
	BaseSetLastNTError(Status);
	return 0;
    }

    /* Check if NOT failing critical errors was requested */
    if (ErrMode & SEM_FAILCRITICALERRORS) {
	/* Mask it out, since the native API works differently */
	ErrMode &= ~SEM_FAILCRITICALERRORS;
    } else {
	/* OR it if the caller didn't, due to different native semantics */
	ErrMode |= SEM_FAILCRITICALERRORS;
    }

    /* Return the mode */
    return ErrMode;
}

/*
 * @implemented
 */
WINAPI LONG UnhandledExceptionFilter(IN PEXCEPTION_POINTERS ExceptionInfo)
{
    static UNICODE_STRING AeDebugKey = RTL_CONSTANT_STRING(L"\\Registry\\Machine"
							   L"\\" REGSTR_PATH_AEDEBUG);

    static BOOLEAN IsSecondChance = FALSE;

    /* Exception data */
    NTSTATUS Status;
    PEXCEPTION_RECORD ExceptionRecord = ExceptionInfo->ExceptionRecord;
    LPTOP_LEVEL_EXCEPTION_FILTER RealFilter;
    LONG RetValue;

    /* Debugger and hard error parameters */
    HANDLE DebugPort = NULL;
    ULONG_PTR ErrorParameters[4];
    ULONG DebugResponse, ErrorResponse;

    /* Post-Mortem "Auto-Execute" (AE) Debugger registry data */
    HANDLE KeyHandle;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING ValueString;
    ULONG Length;
    UCHAR Buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + MAX_PATH * sizeof(WCHAR)];
    PKEY_VALUE_PARTIAL_INFORMATION PartialInfo = (PVOID)Buffer;
    BOOLEAN AeDebugAuto = FALSE;
    PWCHAR AeDebugPath = NULL;
    WCHAR AeDebugCmdLine[MAX_PATH];

    /* Debugger process data */
    BOOL Success;
    HRESULT hRes;
    ULONG PrependLength;
    HANDLE hDebugEvent;
    HANDLE WaitHandles[2];
    STARTUPINFOW StartupInfo;
    PROCESS_INFORMATION ProcessInfo;

    /* In case this is a nested exception, just kill the process */
    if (ExceptionRecord->ExceptionFlags & EXCEPTION_NESTED_CALL) {
	NtTerminateProcess(NtCurrentProcess(), ExceptionRecord->ExceptionCode);
	return EXCEPTION_EXECUTE_HANDLER;
    }

    if ((ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION) &&
	(ExceptionRecord->NumberParameters >= 2)) {
	switch (ExceptionRecord->ExceptionInformation[0]) {
	case EXCEPTION_WRITE_FAULT: {
	    /*
	     * Change the protection on some write attempts,
	     * some InstallShield setups have this bug.
	     */
	    RetValue = BasepCheckForReadOnlyResource(
		(PVOID)ExceptionRecord->ExceptionInformation[1]);
	    if (RetValue == EXCEPTION_CONTINUE_EXECUTION)
		return EXCEPTION_CONTINUE_EXECUTION;
	    break;
	}

	case EXCEPTION_EXECUTE_FAULT:
	    /* FIXME */
	    break;
	}
    }

    /* If the process is being debugged, pass the exception to the debugger */
    Status = NtQueryInformationProcess(NtCurrentProcess(), ProcessDebugPort, &DebugPort,
				       sizeof(DebugPort), NULL);
    if (NT_SUCCESS(Status) && DebugPort) {
	DPRINT("Passing exception to debugger\n");
	return EXCEPTION_CONTINUE_SEARCH;
    }

    /* No debugger present, let's continue... */

    RealFilter = RtlDecodePointer(GlobalTopLevelExceptionFilter);
    if (RealFilter) {
	RetValue = RealFilter(ExceptionInfo);
	if (RetValue != EXCEPTION_CONTINUE_SEARCH)
	    return RetValue;
    }

    /* ReactOS-specific: DPRINT a stack trace */
    PrintStackTrace(ExceptionInfo);

    /*
     * Now pop up an error if needed. Check both the process-wide (Win32)
     * and per-thread error-mode flags (NT).
     */
    if ((GetErrorMode() & SEM_NOGPFAULTERRORBOX) ||
	(RtlGetThreadErrorMode() & RTL_SEM_NOGPFAULTERRORBOX)) {
	/* Do not display the pop-up error box, just transfer control to the exception
	 * handler */
	return EXCEPTION_EXECUTE_HANDLER;
    }

    /* Save exception code and address */
    ErrorParameters[0] = (ULONG_PTR)ExceptionRecord->ExceptionCode;
    ErrorParameters[1] = (ULONG_PTR)ExceptionRecord->ExceptionAddress;

    if (ExceptionRecord->ExceptionCode == STATUS_IN_PAGE_ERROR) {
	/*
	 * Get the underlying status code that resulted in the exception,
	 * and just forget about the type of operation (read/write).
	 */
	ErrorParameters[2] = ExceptionRecord->ExceptionInformation[2];
    } else // if (ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION) or others...
    {
	/* Get the type of operation that caused the access violation */
	ErrorParameters[2] = ExceptionRecord->ExceptionInformation[0];
    }

    /* Save faulting address */
    ErrorParameters[3] = ExceptionRecord->ExceptionInformation[1];

    /*
     * Prepare the hard error dialog: default to only OK
     * in case we do not have any debugger at our disposal.
     */
    DebugResponse = OptionOk;
    AeDebugAuto = FALSE;

    /*
     * Retrieve Post-Mortem Debugger settings from the registry, under:
     * HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug
     * (REGSTR_PATH_AEDEBUG).
     */

    InitializeObjectAttributes(&ObjectAttributes, &AeDebugKey, OBJ_CASE_INSENSITIVE, NULL,
			       NULL);
    Status = NtOpenKey(&KeyHandle, KEY_QUERY_VALUE, &ObjectAttributes);
    if (NT_SUCCESS(Status)) {
	/*
	 * Read the 'Auto' REG_SZ value:
	 * "0" (or any other value): Prompt the user for starting the debugger.
	 * "1": Start the debugger without prompting.
	 */
	RtlInitUnicodeString(&ValueString, REGSTR_VAL_AEDEBUG_AUTO);
	Status = NtQueryValueKey(KeyHandle, &ValueString, KeyValuePartialInformation,
				 PartialInfo, sizeof(Buffer), &Length);
	if (NT_SUCCESS(Status) && (PartialInfo->Type == REG_SZ)) {
	    AeDebugAuto = (*(PWCHAR)PartialInfo->Data == L'1');
	} else {
	    AeDebugAuto = FALSE;
	}

	/*
	 * Read and store the 'Debugger' REG_SZ value. Its usual format is:
	 *    C:\dbgtools\ntsd.exe -p %ld -e %ld -g
	 * with the first and second parameters being respectively
	 * the process ID and a notification event handle.
	 */
	RtlInitUnicodeString(&ValueString, REGSTR_VAL_AEDEBUG_DEBUGGER);
	Status = NtQueryValueKey(KeyHandle, &ValueString, KeyValuePartialInformation,
				 PartialInfo, sizeof(Buffer), &Length);
	if (NT_SUCCESS(Status) && (PartialInfo->Type == REG_SZ)) {
	    /* We hope the string is NULL-terminated */
	    AeDebugPath = (PWCHAR)PartialInfo->Data;

	    /* Skip any prepended whitespace */
	    while (*AeDebugPath && ((*AeDebugPath == L' ') ||
				    (*AeDebugPath == L'\t'))) // iswspace(*AeDebugPath)
	    {
		++AeDebugPath;
	    }

	    if (*AeDebugPath) {
		/* We have a debugger path, we can prompt the user to debug the program */
		DebugResponse = OptionOkCancel;
	    } else {
		/* We actually do not have anything, reset the pointer */
		AeDebugPath = NULL;
	    }
	} else {
	    AeDebugPath = NULL;
	}

	NtClose(KeyHandle);
    }

    // TODO: Start a ReactOS Fault Reporter (unimplemented!)
    //
    // For now we are doing the "old way" (aka Win2k), that is also the fallback
    // case for Windows XP/2003 in case it does not find faultrep.dll to display
    // the nice "Application Error" dialog box: We use a hard error to communicate
    // the problem and prompt the user to continue debugging the application or
    // to terminate it.
    //
    // Since Windows XP/2003, we have the ReportFault API available.
    // See
    // http://www.clausbrod.de/twiki/pub/Blog/DefinePrivatePublic20070616/reportfault.cpp
    // and https://learn.microsoft.com/en-us/windows/win32/wer/using-wer
    // and the legacy ReportFault API:
    // https://learn.microsoft.com/en-us/windows/win32/api/errorrep/nf-errorrep-reportfault
    //
    // NOTE: Starting Vista+, the fault API is constituted of the WerXXX functions.
    //
    // Also see Vostokov's book "Memory Dump Analysis Anthology Collector's Edition,
    // Volume 1" at: https://books.google.fr/books?id=9w2x6NHljg4C&pg=PA115&lpg=PA115

    if (!(AeDebugPath && AeDebugAuto)) {
	/*
	 * Either there is no debugger specified, or the debugger should
	 * not start automatically: display the hard error no matter what.
	 * For a first chance exception, allow continuing or debugging;
	 * for a second chance exception, just debug or kill the process.
	 */
	Status = NtRaiseHardError(STATUS_UNHANDLED_EXCEPTION | HARDERROR_OVERRIDE_ERRORMODE,
				  4, 0, ErrorParameters,
				  (!IsSecondChance ? DebugResponse : OptionOk),
				  (PVOID)&ErrorResponse);
    } else {
	Status = STATUS_SUCCESS;
	ErrorResponse = (AeDebugPath ? ResponseCancel : ResponseOk);
    }

    /*
     * If the user has chosen not to debug the process, or
     * if this is a second chance exception, kill the process.
     */
    if (!NT_SUCCESS(Status) || (ErrorResponse != ResponseCancel) || IsSecondChance)
	goto Quit;

    /* If the exception comes from a CSR Server, kill it (this will lead to ReactOS
     * shutdown) */
    if (BaseRunningInServerProcess) {
	IsSecondChance = TRUE;
	goto Quit;
    }

    /*
     * Attach a debugger to this process. The debugger process is given
     * the process ID of the current process to be debugged, as well as
     * a notification event handle. After being spawned, the debugger
     * initializes and attaches to the process by calling DebugActiveProcess.
     * When the debugger is ready, it signals the notification event,
     * so that we can give it control over the process being debugged,
     * by passing it the exception.
     *
     * See https://learn.microsoft.com/en-us/previous-versions/ms809754(v=msdn.10)
     * and http://www.debuginfo.com/articles/ntsdwatson.html
     * and https://sourceware.org/ml/gdb-patches/2012-08/msg00893.html
     * for more details.
     */

    /* Create an inheritable notification debug event for the debugger */
    InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_INHERIT, NULL, NULL);
    Status = NtCreateEvent(&hDebugEvent, EVENT_ALL_ACCESS, &ObjectAttributes,
			   NotificationEvent, FALSE);
    if (!NT_SUCCESS(Status))
	hDebugEvent = NULL;

    /* Build the debugger command line */

    Success = FALSE;

    /*
     * We will add two longs (process ID and event handle) to the command
     * line. The biggest 32-bit unsigned int (0xFFFFFFFF == 4.294.967.295)
     * takes 10 decimal digits. We then count the terminating NULL.
     */
    Length = (ULONG)wcslen(AeDebugPath) + 2 * 10 + 1;

    /* Check whether the debugger path may be a relative path */
    if ((*AeDebugPath != L'"') &&
	(RtlDetermineDosPathNameType_U(AeDebugPath) == RtlPathTypeRelative)) {
	/* Relative path, prepend SystemRoot\System32 */
	PrependLength = (ULONG)wcslen(SharedUserData->NtSystemRoot) +
			10 /* == wcslen(L"\\System32\\") */;
	if (PrependLength + Length <= ARRAYSIZE(AeDebugCmdLine)) {
	    hRes = StringCchPrintfW(AeDebugCmdLine, PrependLength + 1, L"%s\\System32\\",
				  SharedUserData->NtSystemRoot);
	    Success = SUCCEEDED(hRes);
	}
    } else {
	/* Full path */
	PrependLength = 0;
	if (Length <= ARRAYSIZE(AeDebugCmdLine))
	    Success = TRUE;
    }

    /* Format the command line */
    if (Success) {
	hRes = StringCchPrintfW(
	    &AeDebugCmdLine[PrependLength], Length, AeDebugPath,
	    HandleToUlong(
		NtCurrentTeb()->NtTib.ClientId.UniqueProcess), // GetCurrentProcessId()
	    hDebugEvent);
	Success = SUCCEEDED(hRes);
    }

    /* Start the debugger */
    if (Success) {
	DPRINT1("\nStarting debugger: '%S'\n", AeDebugCmdLine);

	RtlZeroMemory(&StartupInfo, sizeof(StartupInfo));
	RtlZeroMemory(&ProcessInfo, sizeof(ProcessInfo));

	StartupInfo.cb = sizeof(StartupInfo);
	StartupInfo.lpDesktop = L"WinSta0\\Default";

	Success = CreateProcessW(NULL, AeDebugCmdLine, NULL, NULL, TRUE, 0, NULL, NULL,
				 &StartupInfo, &ProcessInfo);
    }

    if (Success) {
	WaitHandles[0] = hDebugEvent;
	WaitHandles[1] = ProcessInfo.hProcess;

	/* Loop until the debugger gets ready or terminates unexpectedly */
	do {
	    /* Alertable wait */
	    Status = NtWaitForMultipleObjects(ARRAYSIZE(WaitHandles), WaitHandles,
					      WaitAny, TRUE, NULL);
	} while ((Status == STATUS_ALERTED) || (Status == STATUS_USER_APC));

	/*
	 * The debugger terminated unexpectedly and we cannot attach to it.
	 * Kill the process being debugged.
	 */
	if (Status == STATUS_WAIT_1) {
	    /* Be sure there is no other debugger attached */
	    Status = NtQueryInformationProcess(NtCurrentProcess(), ProcessDebugPort,
					       &DebugPort, sizeof(DebugPort), NULL);
	    if (!NT_SUCCESS(Status) || !DebugPort) {
		/* No debugger is attached, kill the process at next round */
		IsSecondChance = TRUE;
	    }
	}

	CloseHandle(ProcessInfo.hThread);
	CloseHandle(ProcessInfo.hProcess);

	if (hDebugEvent)
	    NtClose(hDebugEvent);

	return EXCEPTION_CONTINUE_SEARCH;
    }

    /* We failed starting the debugger, close the event handle and kill the process */

    if (hDebugEvent)
	NtClose(hDebugEvent);

    IsSecondChance = TRUE;

Quit:
    /* If this is a second chance exception, kill the process */
    if (IsSecondChance)
	NtTerminateProcess(NtCurrentProcess(), ExceptionRecord->ExceptionCode);

    /* Otherwise allow handling exceptions in first chance */

    /*
     * Returning EXCEPTION_EXECUTE_HANDLER means that the code in
     * the __except block will be executed. Normally this will end up in a
     * Terminate process.
     */

    return EXCEPTION_EXECUTE_HANDLER;
}

/*
 * @implemented
 */
WINAPI VOID RaiseException(_In_ DWORD dwExceptionCode, _In_ DWORD dwExceptionFlags,
			   _In_ DWORD nNumberOfArguments,
			   _In_opt_ const ULONG_PTR *lpArguments)
{
    EXCEPTION_RECORD ExceptionRecord;

    /* Setup the exception record */
    RtlZeroMemory(&ExceptionRecord, sizeof(ExceptionRecord));
    ExceptionRecord.ExceptionCode = dwExceptionCode;
    ExceptionRecord.ExceptionRecord = NULL;
    ExceptionRecord.ExceptionAddress = (PVOID)RaiseException;
    ExceptionRecord.ExceptionFlags = dwExceptionFlags & EXCEPTION_NONCONTINUABLE;

    /* Check if we have arguments */
    if (!lpArguments) {
	/* We don't */
	ExceptionRecord.NumberParameters = 0;
    } else {
	/* We do, normalize the count */
	if (nNumberOfArguments > EXCEPTION_MAXIMUM_PARAMETERS)
	    nNumberOfArguments = EXCEPTION_MAXIMUM_PARAMETERS;

	/* Set the count of parameters and copy them */
	ExceptionRecord.NumberParameters = nNumberOfArguments;
	RtlCopyMemory(ExceptionRecord.ExceptionInformation, lpArguments,
		      nNumberOfArguments * sizeof(ULONG_PTR));
    }

    /* Better handling of Delphi Exceptions... a ReactOS Hack */
    if (dwExceptionCode == 0xeedface || dwExceptionCode == 0xeedfade) {
	DPRINT1("Delphi Exception at address: %zu\n",
		ExceptionRecord.ExceptionInformation[0]);
	DPRINT1("Exception-Object: %zu\n", ExceptionRecord.ExceptionInformation[1]);
	DPRINT1("Exception text: %zx\n", ExceptionRecord.ExceptionInformation[2]);
    }

    /* Raise the exception */
    RtlRaiseException(&ExceptionRecord);
}

/*
 * @implemented
 */
WINAPI UINT SetErrorMode(IN UINT uMode)
{
    UINT PrevErrMode, NewMode;

    /* Get the previous mode */
    PrevErrMode = GetErrorMode();
    NewMode = uMode;

    /* Check if failing critical errors was requested */
    if (NewMode & SEM_FAILCRITICALERRORS) {
	/* Mask it out, since the native API works differently */
	NewMode &= ~SEM_FAILCRITICALERRORS;
    } else {
	/* OR it if the caller didn't, due to different native semantics */
	NewMode |= SEM_FAILCRITICALERRORS;
    }

    /* Always keep no alignment faults if they were set */
    NewMode |= (PrevErrMode & SEM_NOALIGNMENTFAULTEXCEPT);

    /* Set the new mode */
    NtSetInformationProcess(NtCurrentProcess(), ProcessDefaultHardErrorMode,
			    (PVOID)&NewMode, sizeof(NewMode));

    /* Return the previous mode */
    return PrevErrMode;
}

/*
 * @implemented
 */
WINAPI DECLSPEC_HOTPATCH LPTOP_LEVEL_EXCEPTION_FILTER
SetUnhandledExceptionFilter(IN LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter)
{
    PVOID EncodedPointer, EncodedOldPointer;

    EncodedPointer = RtlEncodePointer(lpTopLevelExceptionFilter);
    EncodedOldPointer = InterlockedExchangePointer(
	(PVOID *)&GlobalTopLevelExceptionFilter, EncodedPointer);
    return RtlDecodePointer(EncodedOldPointer);
}

/*
 * @implemented
 */
WINAPI BOOL IsBadReadPtr(IN LPCVOID Ptr, IN UINT_PTR Size)
{
    ULONG PageSize;
    BOOLEAN Result = FALSE;
    volatile CHAR *Current;
    PCHAR Last;

    /* Quick cases */
    if (!Size)
	return FALSE;
    if (!Ptr)
	return TRUE;

    /* Get the page size */
    PageSize = BaseStaticServerData->SysInfo.PageSize;

    /* Calculate start and end */
    Current = (volatile CHAR *)Ptr;
    Last = (PCHAR)((ULONG_PTR)Ptr + Size - 1);

    /* Another quick failure case */
    if (Last < Current)
	return TRUE;

    /* Enter SEH */
    __try {
	/* Do an initial probe */
	*Current;

	/* Align the addresses */
	Current = (volatile CHAR *)ALIGN_DOWN_POINTER_BY(Current, PageSize);
	Last = (PCHAR)ALIGN_DOWN_POINTER_BY(Last, PageSize);

	/* Probe the entire range */
	while (Current != Last) {
	    Current += PageSize;
	    *Current;
	}
    } __except (EXCEPTION_EXECUTE_HANDLER) {
	/* We hit an exception, so return true */
	Result = TRUE;
    }

    /* Return exception status */
    return Result;
}

/*
 * @implemented
 */
NTAPI BOOL IsBadHugeReadPtr(LPCVOID Ptr, UINT_PTR Size)
{
    /* Implementation is the same on 32-bit */
    return IsBadReadPtr(Ptr, Size);
}

/*
 * @implemented
 */
NTAPI BOOL IsBadCodePtr(FARPROC Ptr)
{
    /* Executing has the same privileges as reading */
    return IsBadReadPtr((LPVOID)Ptr, 1);
}

/*
 * @implemented
 */
NTAPI BOOL IsBadWritePtr(IN LPVOID Ptr, IN UINT_PTR Size)
{
    ULONG PageSize;
    BOOLEAN Result = FALSE;
    volatile CHAR *Current;
    PCHAR Last;

    /* Quick cases */
    if (!Size)
	return FALSE;
    if (!Ptr)
	return TRUE;

    /* Get the page size */
    PageSize = BaseStaticServerData->SysInfo.PageSize;

    /* Calculate start and end */
    Current = (volatile CHAR *)Ptr;
    Last = (PCHAR)((ULONG_PTR)Ptr + Size - 1);

    /* Another quick failure case */
    if (Last < Current)
	return TRUE;

    /* Enter SEH */
    __try {
	/* Do an initial probe */
	*Current = *Current;

	/* Align the addresses */
	Current = (volatile CHAR *)ALIGN_DOWN_POINTER_BY(Current, PageSize);
	Last = (PCHAR)ALIGN_DOWN_POINTER_BY(Last, PageSize);

	/* Probe the entire range */
	while (Current != Last) {
	    Current += PageSize;
	    *Current = *Current;
	}
    } __except (EXCEPTION_EXECUTE_HANDLER) {
	/* We hit an exception, so return true */
	Result = TRUE;
    }

    /* Return exception status */
    return Result;
}

/*
 * @implemented
 */
NTAPI BOOL IsBadHugeWritePtr(IN LPVOID Ptr, IN UINT_PTR Size)
{
    /* Implementation is the same on 32-bit */
    return IsBadWritePtr(Ptr, Size);
}

/*
 * @implemented
 */
NTAPI BOOL IsBadStringPtrW(IN LPCWSTR Ptr, IN UINT_PTR NumWchars)
{
    BOOLEAN Result = FALSE;
    volatile WCHAR *Current;
    PWCHAR Last;
    WCHAR Char;

    /* Quick cases */
    if (!NumWchars)
	return FALSE;
    if (!Ptr)
	return TRUE;

    /* Calculate start and end */
    Current = (volatile WCHAR *)Ptr;
    Last = (PWCHAR)((ULONG_PTR)Ptr + (NumWchars * 2) - 2);

    /* Enter SEH */
    __try {
	/* Probe the entire range */
	Char = *Current++;
	while ((Char) && (Current != Last))
	    Char = *Current++;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
	/* We hit an exception, so return true */
	Result = TRUE;
    }

    /* Return exception status */
    return Result;
}

/*
 * @implemented
 */
NTAPI BOOL IsBadStringPtrA(IN LPCSTR Ptr, IN UINT_PTR NumChars)
{
    BOOLEAN Result = FALSE;
    volatile CHAR *Current;
    PCHAR Last;
    CHAR Char;

    /* Quick cases */
    if (!NumChars)
	return FALSE;
    if (!Ptr)
	return TRUE;

    /* Calculate start and end */
    Current = (volatile CHAR *)Ptr;
    Last = (PCHAR)((ULONG_PTR)Ptr + NumChars - 1);

    /* Enter SEH */
    __try {
	/* Probe the entire range */
	Char = *Current++;
	while ((Char) && (Current != Last))
	    Char = *Current++;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
	/* We hit an exception, so return true */
	Result = TRUE;
    }

    /* Return exception status */
    return Result;
}

/*
 * @implemented
 */
WINAPI VOID SetLastError(IN DWORD dwErrCode)
{
    /* Break if a debugger requested checking for this error code */
    if ((g_dwLastErrorToBreakOn) && (g_dwLastErrorToBreakOn == dwErrCode))
	DbgBreakPoint();

    /* Set last error if it's a new error */
    if (NtCurrentTeb()->Win32.LastErrorValue != dwErrCode)
	NtCurrentTeb()->Win32.LastErrorValue = dwErrCode;
}

/*
 * @implemented
 */
WINAPI DWORD GetLastError(VOID)
{
    /* Return the current value */
    return NtCurrentTeb()->Win32.LastErrorValue;
}

/* EOF */
