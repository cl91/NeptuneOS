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

NTAPI VOID NtProcessStartup(PPEB Peb)
{
    HANDLE FileHandle = NULL;
    HANDLE SectionHandle = NULL;
    HANDLE ProcessHandle = NULL;
    HANDLE ThreadHandle = NULL;

    UNICODE_STRING FileName;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    NTSTATUS Status;

    WCHAR NtPath[] = L"\\??\\A:\\psxdll.so";
    RtlInitUnicodeString(&FileName, NtPath);
    InitializeObjectAttributes(&ObjectAttributes, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    /* Open executable file */
    Status = NtOpenFile(&FileHandle,
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

    /* Wait for process to finish */
    Status = NtWaitForSingleObject(ProcessHandle, FALSE, NULL);
    CHECK_STATUS(Status, "NtWaitForSingleObject");

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

    NtTerminateProcess(NtCurrentProcess(), Status);
}

