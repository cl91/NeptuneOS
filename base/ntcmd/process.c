#include "ntcmd.h"

/*
 *****************************************************************************
 * CreateNativeProcess - Create a native process
 * FileName: full path to .exe, in DOS format
 * CmdLine: arguments for process
 *
 * Returns: STATUS_SUCCESS or STATUS_UNSUCCESSFUL
 *****************************************************************************
 */
NTSTATUS CreateNativeProcess(IN PCWSTR FileName, IN PCWSTR CmdLine,
			     OUT PHANDLE hProcess)
{
    UNICODE_STRING NtFileName;
    PCWSTR FilePath;
    NTSTATUS Status;		// Status
    UNICODE_STRING ImageName;	// ImageName
    UNICODE_STRING ImagePath;	// Nt ImagePath
    UNICODE_STRING DllPath;	// Nt DllPath (DOS Name)
    UNICODE_STRING UnicodeCmdLine;	// Nt CommandLine
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;	// ProcessParameters
    RTL_USER_PROCESS_INFORMATION ProcessInformation = { 0 };	// ProcessInformation
    WCHAR Env[2] = { 0, 0 };	// Process Envirnoment
    PKUSER_SHARED_DATA SharedData = (PKUSER_SHARED_DATA)USER_SHARED_DATA;	// Kernel Shared Data

    *hProcess = NULL;

    RtlDosPathNameToNtPathName_U(FileName, &NtFileName, &FilePath, NULL);

    RtlInitUnicodeString(&ImagePath, NtFileName.Buffer);	// Image path
    RtlInitUnicodeString(&ImageName, FilePath);	// Image name
    RtlInitUnicodeString(&DllPath, SharedData->NtSystemRoot);	// DLL Path is %wsystemRoot%
    RtlInitUnicodeString(&UnicodeCmdLine, CmdLine);	// Command Line parameters

    Status = RtlCreateProcessParameters(&ProcessParameters, &ImageName, &DllPath,
					&DllPath, &UnicodeCmdLine, Env, 0, 0, 0, 0);

    if (!NT_SUCCESS(Status)) {
	RtlCliDisplayString("RtlCreateProcessParameters failed\n");
	return STATUS_UNSUCCESSFUL;
    }

    DbgPrint("Launching Process: %wZ, DllPath=%wZ, CmdLine=%wZ", &ImageName,
	     &DllPath, &UnicodeCmdLine);
    Status = RtlCreateUserProcess(&ImagePath, OBJ_CASE_INSENSITIVE,
				  ProcessParameters, NULL, NULL, NULL, FALSE,
				  NULL, NULL, &ProcessInformation);

    if (!NT_SUCCESS(Status)) {
	RtlCliDisplayString("RtlCreateUserProcess failed\n");
	return STATUS_UNSUCCESSFUL;
    }

    Status = NtResumeThread(ProcessInformation.ThreadHandle, NULL);

    if (!NT_SUCCESS(Status)) {
	RtlCliDisplayString("NtResumeThread failed\n");
	return STATUS_UNSUCCESSFUL;
    }
    NtClose(ProcessInformation.ThreadHandle);

    *hProcess = ProcessInformation.ProcessHandle;

    return STATUS_SUCCESS;
}
