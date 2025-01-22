/*
 * COPYRIGHT:         See COPYING in the top level directory
 * PROJECT:           ReactOS system libraries
 * FILE:              lib/rtl/process.c
 * PURPOSE:           Process functions
 * PROGRAMMER:        Alex Ionescu (alex@relsoft.net)
 *                    Ariadne (ariadne@xs4all.nl)
 *                    Eric Kohl
 */

/* INCLUDES ****************************************************************/

#include "rtlp.h"

/* INTERNAL FUNCTIONS *******************************************************/

static NTSTATUS RtlpMapFile(PUNICODE_STRING ImageFileName,
			    ULONG Attributes,
			    PHANDLE Section)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    NTSTATUS Status;
    HANDLE hFile = NULL;
    IO_STATUS_BLOCK IoStatusBlock;

    /* Open the Image File */
    InitializeObjectAttributes(&ObjectAttributes, ImageFileName,
			       Attributes & (OBJ_CASE_INSENSITIVE |
					     OBJ_INHERIT), NULL, NULL);
    Status = NtOpenFile(&hFile, SYNCHRONIZE | FILE_EXECUTE | FILE_READ_DATA,
			&ObjectAttributes, &IoStatusBlock,
			FILE_SHARE_DELETE | FILE_SHARE_READ,
			FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("Failed to read image file from disk, Status = 0x%08X\n",
		Status);
	return Status;
    }

    /* Now create a section for this image */
    Status = NtCreateSection(Section, SECTION_ALL_ACCESS,
			     NULL, NULL, PAGE_EXECUTE, SEC_IMAGE, hFile);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("Failed to create section for image file, Status = 0x%08X\n",
		Status);
    }

    NtClose(hFile);
    return Status;
}

/* FUNCTIONS ****************************************************************/

static NTSTATUS RtlpInitEnvironment(HANDLE ProcessHandle,
				    PPEB Peb,
				    PRTL_USER_PROCESS_PARAMETERS ProcessParameters)
{
    NTSTATUS Status;
    PVOID BaseAddress = NULL;
    SIZE_T EnviroSize;
    SIZE_T Size;
    PWCHAR Environment = NULL;
    DPRINT("RtlpInitEnvironment(ProcessHandle: %p, Peb: %p Params: %p)\n",
	   ProcessHandle, Peb, ProcessParameters);

    /* Give the caller 1MB if requested */
    if (ProcessParameters->Flags & RTL_USER_PROCESS_PARAMETERS_RESERVE_1MB) {
	/* Give 1MB starting at 0x4 */
	BaseAddress = (PVOID)4;
	EnviroSize = (1024 * 1024) - 256;
	Status = NtAllocateVirtualMemory(ProcessHandle, &BaseAddress, 0,
					 &EnviroSize, MEM_RESERVE, PAGE_READWRITE);
	if (!NT_SUCCESS(Status)) {
	    DPRINT1("Failed to reserve 1MB for process parameters\n");
	    return Status;
	}
    }

    /* Find the end of the Enviroment Block */
    if ((Environment = (PWCHAR)ProcessParameters->Environment)) {
	while (*Environment++)
	    while (*Environment++);

	/* Calculate the size of the block */
	EnviroSize = (ULONG)((ULONG_PTR)Environment -
			     (ULONG_PTR)ProcessParameters->Environment);

	/* Allocate and Initialize new Environment Block */
	Size = EnviroSize;
	Status = NtAllocateVirtualMemory(ProcessHandle, &BaseAddress, 0, &Size,
					 MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!NT_SUCCESS(Status)) {
	    DPRINT1("Failed to allocate Environment Block\n");
	    return Status;
	}

	/* Write the Environment Block */
	NtWriteVirtualMemory(ProcessHandle, BaseAddress,
			     ProcessParameters->Environment, EnviroSize, NULL);

	/* Save pointer */
	ProcessParameters->Environment = BaseAddress;
    }

    /* Now allocate space for the Parameter Block */
    BaseAddress = NULL;
    Size = ProcessParameters->MaximumLength;
    Status = NtAllocateVirtualMemory(ProcessHandle, &BaseAddress, 0, &Size,
				     MEM_COMMIT, PAGE_READWRITE);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("Failed to allocate Parameter Block\n");
	return Status;
    }

    /* Write the Parameter Block */
    Status = NtWriteVirtualMemory(ProcessHandle, BaseAddress, ProcessParameters,
				  ProcessParameters->Length, NULL);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("Failed to write the Parameter Block\n");
	return Status;
    }

    /* Write pointer to Parameter Block */
    Status = NtWriteVirtualMemory(ProcessHandle, &Peb->ProcessParameters,
				  &BaseAddress, sizeof(BaseAddress), NULL);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("Failed to write pointer to Parameter Block\n");
	return Status;
    }

    /* Return */
    return STATUS_SUCCESS;
}

/*
 * @implemented
 *
 * Creates a process and its initial thread.
 *
 * NOTES:
 *  - The first thread is created suspended, so it needs a manual resume!!!
 *  - If ParentProcess is NULL, current process is used
 *  - ProcessParameters must be normalized
 *  - Attributes are object attribute flags used when opening the ImageFileName.
 *    Valid flags are OBJ_INHERIT and OBJ_CASE_INSENSITIVE.
 *
 * -Gunnar
 */
NTAPI NTSTATUS RtlCreateUserProcess(IN PUNICODE_STRING ImageFileName,
				    IN ULONG Attributes,
				    IN OUT PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
				    IN PSECURITY_DESCRIPTOR ProcessSecurityDescriptor OPTIONAL,
				    IN PSECURITY_DESCRIPTOR ThreadSecurityDescriptor OPTIONAL,
				    IN HANDLE ParentProcess OPTIONAL,
				    IN BOOLEAN InheritHandles,
				    IN HANDLE DebugPort OPTIONAL,
				    IN HANDLE ExceptionPort OPTIONAL,
				    OUT PRTL_USER_PROCESS_INFORMATION ProcessInfo)
{
    NTSTATUS Status;
    HANDLE hSection;
    PROCESS_BASIC_INFORMATION ProcessBasicInfo;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING DebugString = RTL_CONSTANT_STRING(L"\\WindowsSS");
    DPRINT("RtlCreateUserProcess: %wZ\n", ImageFileName);

    /* Map and Load the File */
    Status = RtlpMapFile(ImageFileName, Attributes, &hSection);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("Could not map process image\n");
	return Status;
    }

    /* Clean out the current directory handle if we won't use it */
    if (!InheritHandles)
	ProcessParameters->CurrentDirectory.Handle = NULL;

    /* Use us as parent if none other specified */
    if (!ParentProcess)
	ParentProcess = NtCurrentProcess();

    /* Initialize the Object Attributes */
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL,
			       ProcessSecurityDescriptor);

    /*
     * If FLG_ENABLE_CSRDEBUG is used, then CSRSS is created under the
     * watch of WindowsSS
     */
    if ((RtlGetNtGlobalFlags() & FLG_ENABLE_CSRDEBUG) &&
	(wcsstr(ImageFileName->Buffer, L"csrss"))) {
	ObjectAttributes.ObjectName = &DebugString;
    }

    /* Create Kernel Process Object */
    Status = NtCreateProcess(&ProcessInfo->ProcessHandle,
			     PROCESS_ALL_ACCESS,
			     &ObjectAttributes,
			     ParentProcess,
			     InheritHandles,
			     hSection, DebugPort, ExceptionPort);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("Could not create Kernel Process Object\n");
	NtClose(hSection);
	return Status;
    }

    /* Get some information on the image */
    Status = NtQuerySection(hSection,
			    SectionImageInformation,
			    &ProcessInfo->ImageInformation,
			    sizeof(SECTION_IMAGE_INFORMATION), NULL);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("Could not query Section Info\n");
	NtClose(ProcessInfo->ProcessHandle);
	NtClose(hSection);
	return Status;
    }

    /* Get some information about the process */
    Status = NtQueryInformationProcess(ProcessInfo->ProcessHandle,
				       ProcessBasicInformation,
				       &ProcessBasicInfo,
				       sizeof(ProcessBasicInfo), NULL);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("Could not query Process Info\n");
	NtClose(ProcessInfo->ProcessHandle);
	NtClose(hSection);
	return Status;
    }

    /* Duplicate the standard handles */
    Status = STATUS_SUCCESS;
    __try {
	if (ProcessParameters->StandardInput) {
	    Status = NtDuplicateObject(ParentProcess,
				       ProcessParameters->StandardInput,
				       ProcessInfo->ProcessHandle,
				       &ProcessParameters->StandardInput,
				       0,
				       0,
				       DUPLICATE_SAME_ACCESS |
				       DUPLICATE_SAME_ATTRIBUTES);
	    if (!NT_SUCCESS(Status)) {
		__leave;
	    }
	}

	if (ProcessParameters->StandardOutput) {
	    Status = NtDuplicateObject(ParentProcess,
				       ProcessParameters->StandardOutput,
				       ProcessInfo->ProcessHandle,
				       &ProcessParameters->StandardOutput,
				       0,
				       0,
				       DUPLICATE_SAME_ACCESS |
				       DUPLICATE_SAME_ATTRIBUTES);
	    if (!NT_SUCCESS(Status)) {
		__leave;
	    }
	}

	if (ProcessParameters->StandardError) {
	    Status = NtDuplicateObject(ParentProcess,
				       ProcessParameters->StandardError,
				       ProcessInfo->ProcessHandle,
				       &ProcessParameters->StandardError,
				       0,
				       0,
				       DUPLICATE_SAME_ACCESS |
				       DUPLICATE_SAME_ATTRIBUTES);
	    if (!NT_SUCCESS(Status)) {
		__leave;
	    }
	}
    } __finally {
	if (!NT_SUCCESS(Status)) {
	    NtClose(ProcessInfo->ProcessHandle);
	    NtClose(hSection);
	}
    }

    if (!NT_SUCCESS(Status))
	return Status;

    /* Create Process Environment */
    Status = RtlpInitEnvironment(ProcessInfo->ProcessHandle,
				 ProcessBasicInfo.PebBaseAddress,
				 ProcessParameters);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("Could not Create Process Environment\n");
	NtClose(ProcessInfo->ProcessHandle);
	NtClose(hSection);
	return Status;
    }

    /* Create the first Thread */
    Status = RtlCreateUserThread(ProcessInfo->ProcessHandle,
				 ThreadSecurityDescriptor, TRUE,
				 ProcessInfo->ImageInformation.ZeroBits,
				 ProcessInfo->ImageInformation.MaximumStackSize,
				 ProcessInfo->ImageInformation.CommittedStackSize,
				 ProcessInfo->ImageInformation.TransferAddress,
				 ProcessBasicInfo.PebBaseAddress,
				 &ProcessInfo->ThreadHandle,
				 &ProcessInfo->ClientId);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("Could not Create Thread\n");
	NtClose(ProcessInfo->ProcessHandle);
	NtClose(hSection);	/* Don't try to optimize this on top! */
	return Status;
    }

    /* Close the Section Handle and return */
    NtClose(hSection);
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTAPI PVOID RtlEncodePointer(IN PVOID Pointer)
{
    ULONG Cookie;
    NTSTATUS Status;

    Status = NtQueryInformationProcess(NtCurrentProcess(),
				       ProcessCookie,
				       &Cookie, sizeof(Cookie), NULL);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("Failed to receive the process cookie! Status: 0x%x\n",
		Status);
	return Pointer;
    }

    return (PVOID) ((ULONG_PTR) Pointer ^ Cookie);
}

/*
 * @implemented
 */
NTAPI PVOID RtlDecodePointer(IN PVOID Pointer)
{
    return RtlEncodePointer(Pointer);
}

/*
 * @implemented
 */
NTAPI PVOID RtlEncodeSystemPointer(IN PVOID Pointer)
{
    return (PVOID) ((ULONG_PTR) Pointer ^ SharedUserData->Cookie);
}

/*
 * @implemented
 */
NTAPI PVOID RtlDecodeSystemPointer(IN PVOID Pointer)
{
    return RtlEncodeSystemPointer(Pointer);
}

/*
 * @implemented
 *
 * NOTES:
 *   Implementation based on the documentation from:
 *   http://www.geoffchappell.com/studies/windows/win32/ntdll/api/rtl/peb/setprocessiscritical.htm
 */
__cdecl NTSTATUS RtlSetProcessIsCritical(IN BOOLEAN NewValue,
					 OUT PBOOLEAN OldValue OPTIONAL,
					 IN BOOLEAN NeedBreaks)
{
    ULONG BreakOnTermination;

    /* Initialize to FALSE */
    if (OldValue)
	*OldValue = FALSE;

    /* Fail, if the critical breaks flag is required but is not set */
    if ((NeedBreaks) &&
	!(NtCurrentPeb()->NtGlobalFlag & FLG_ENABLE_SYSTEM_CRIT_BREAKS)) {
	return STATUS_UNSUCCESSFUL;
    }

    /* Check if the caller wants the old value */
    if (OldValue) {
	/* Query and return the old break on termination flag for the process */
	NtQueryInformationProcess(NtCurrentProcess(),
				  ProcessBreakOnTermination,
				  &BreakOnTermination,
				  sizeof(ULONG), NULL);
	*OldValue = (BOOLEAN) BreakOnTermination;
    }

    /* Set the break on termination flag for the process */
    BreakOnTermination = NewValue;
    return NtSetInformationProcess(NtCurrentProcess(),
				   ProcessBreakOnTermination,
				   &BreakOnTermination, sizeof(ULONG));
}

NTAPI ULONG RtlGetCurrentProcessorNumber(VOID)
{
    /* Forward to kernel */
    return NtGetCurrentProcessorNumber();
}
