#include <psxss.h>
#include <stdio.h>

#define CHECK_STATUS(Status, Msg)			\
    if (!NT_SUCCESS(Status)) {				\
	CHAR MsgBuf[256];				\
        snprintf(MsgBuf, sizeof(MsgBuf),		\
		 "%s failed: 0x%08X\n", Msg, Status);	\
	NtDisplayStringA(MsgBuf);			\
        goto out;					\
    }

static NTSTATUS PsxCreatePort(OUT PHANDLE PortHandle,
			      OUT PHANDLE CommPortHandle)
{
    UNICODE_STRING ObjectPath;
    OBJECT_ATTRIBUTES ObjectAttributes;

    RtlInitUnicodeString(&ObjectPath, L"\\PsxssApi");
    InitializeObjectAttributes(&ObjectAttributes, &ObjectPath,
			       OBJ_PERMANENT, NULL, NULL);

    NTSTATUS Status = NtCreatePort(PortHandle, CommPortHandle,
				   &ObjectAttributes, 256);
    CHECK_STATUS(Status, "NtCreatePort");

out:
    return Status;
}

static NTSTATUS PsxCreateClientProcess()
{
    HANDLE FileHandle = NULL;
    HANDLE SectionHandle = NULL;
    HANDLE ProcessHandle = NULL;
    HANDLE ThreadHandle = NULL;

    UNICODE_STRING FileName;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;

    WCHAR NtPath[] = L"\\??\\A:\\psxdll.so";
    RtlInitUnicodeString(&FileName, NtPath);
    InitializeObjectAttributes(&ObjectAttributes, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    /* Open executable file */
    NTSTATUS Status = NtOpenFile(&FileHandle,
				 FILE_EXECUTE | SYNCHRONIZE,
				 &ObjectAttributes,
				 &IoStatusBlock,
				 FILE_SHARE_READ,
				 FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    CHECK_STATUS(Status, "NtOpenFile");

    /* Create image section */
    Status = NtCreateSection(&SectionHandle,
                             SECTION_ALL_ACCESS,
                             NULL,
                             NULL,
                             PAGE_READONLY,
                             SEC_IMAGE,
                             FileHandle);
    CHECK_STATUS(Status, "NtCreateSection");

    /* Create process from section */
    Status = NtCreateProcess(&ProcessHandle,
			     PROCESS_ALL_ACCESS,
			     NULL,
			     NtCurrentProcess(),
			     FALSE,
			     SectionHandle,
			     NULL,
			     NULL);
    CHECK_STATUS(Status, "NtCreateProcess");

    /* Query image base address */
    SECTION_IMAGE_INFORMATION ImageInfo;
    Status = NtQuerySection(SectionHandle,
                            SectionImageInformation,
                            &ImageInfo,
                            sizeof(ImageInfo),
                            NULL);
    CHECK_STATUS(Status, "NtQuerySection");

    /* Create thread at EntryPoint */
    Status = RtlCreateUserThread(ProcessHandle,
				 NULL,
				 FALSE,
				 0,
				 64 * 1024,
				 16 * 1024,
				 ImageInfo.TransferAddress,
				 NULL,
				 &ThreadHandle,
				 NULL);
    CHECK_STATUS(Status, "RtlCreateUserThread");

    /* /\* Wait for process to finish *\/ */
    /* Status = NtWaitForSingleObject(ProcessHandle, FALSE, NULL); */
    /* CHECK_STATUS(Status, "NtWaitForSingleObject"); */

out:
    // Cleanup
    if (ThreadHandle) {
	NtClose(ThreadHandle);
    }
    if (ProcessHandle) {
	NtClose(ProcessHandle);
    }
    if (SectionHandle) {
	NtClose(SectionHandle);
    }
    if (FileHandle) {
	NtClose(FileHandle);
    }

    return Status;
}

NTAPI VOID NtProcessStartup(PPEB Peb)
{
    HANDLE PortHandle = NULL;
    HANDLE CommPortHandle = NULL;
    NTSTATUS Status = PsxCreatePort(&PortHandle, &CommPortHandle);
    CHECK_STATUS(Status, "PsxCreatePort");

    Status = PsxCreateClientProcess();
    CHECK_STATUS(Status, "PsxCreateClientProcess");

    CLIENT_ID ClientId = {};
    Status = NtListenPort(PortHandle, &ClientId, NULL, 0, NULL);
    CHECK_STATUS(Status, "NtListenPort");

    Status = NtAcceptPort(NULL, PortHandle, (ULONG_PTR)ClientId.UniqueThread, &ClientId,
			  TRUE, NULL, NULL);
    CHECK_STATUS(Status, "NtAcceptPort");

    while (TRUE) {
	ULONG_PTR PortContext = 0;
	PORT_MESSAGE PortMessage;
	Status = NtReceivePort(CommPortHandle, &PortContext, &PortMessage, NULL);
	if (!NT_SUCCESS(Status)) {
	    goto out;
	}
	DbgPrint("Got message length 0x%x\n", PortMessage.TotalLength);
    }

out:
    NtTerminateProcess(NtCurrentProcess(), Status);
}

