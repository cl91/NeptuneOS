#include "umtests.h"

static CHAR Buffer[1440 * 1024];

NTSTATUS TestFloppyDriver()
{
    HANDLE hFloppy;
    UNICODE_STRING FloppyDevice;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;

    /* Open the device */
    LARGE_INTEGER AllocationSize = { .QuadPart = 0x911 };
    RtlInitUnicodeString(&FloppyDevice, L"\\Device\\Floppy0\\test");
    InitializeObjectAttributes(&ObjectAttributes, &FloppyDevice, 0, NULL, NULL);
    NTSTATUS Status = NtCreateFile(&hFloppy, FILE_READ_DATA | FILE_WRITE_DATA,
				   &ObjectAttributes, &IoStatusBlock, &AllocationSize, 0,
				   FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
				   0, NULL, 0);
    if (!NT_SUCCESS(Status)) {
	VgaPrint("Failed to create device handle for fdc.sys. Status = 0x%x\n", Status);
	return Status;
    }

    LARGE_INTEGER ByteOffset;
    RtlZeroMemory(&ByteOffset, sizeof(ByteOffset));

    /* Try to read the data */
    VgaPrint("Writing floppy... ");
    snprintf(Buffer, 128, "hello, world!\n");
    Status = NtWriteFile(hFloppy, NULL, NULL, NULL, &IoStatusBlock,
			 Buffer, 0x1000, &ByteOffset, NULL);
    if (!NT_SUCCESS(Status)) {
	VgaPrint("FAILED. Status = 0x%x\n", Status);
	return Status;
    }
    ULONG FileSize = IoStatusBlock.Information;

    VgaPrint("first bytes (see serial for full dump): %02x %02x %02x %02x.\n",
	     Buffer[0], Buffer[1], Buffer[2], Buffer[3]);

    Status = NtFlushBuffersFile(hFloppy, &IoStatusBlock);
    if (!NT_SUCCESS(Status)) {
	VgaPrint("Failed to flush buffers for %wZ, status = 0x%x\n",
		 &FloppyDevice, Status);
	return Status;
    }

    for (ULONG i = 0; i <= FileSize / 16; i++) {
	PUSHORT Row = (PUSHORT)(Buffer + 16*i);
	DbgPrint("%07x %04x %04x %04x %04x %04x %04x %04x %04x\n",
		 16*i, Row[0], Row[1], Row[2], Row[3],
		 Row[4], Row[5], Row[6], Row[7]);
    }

    for (ULONG i = FileSize / 16 + 1; i < ARRAYSIZE(Buffer) / 16; i++) {
	PUSHORT Row = (PUSHORT)(Buffer + 16*i);
	PULONG64 Row64 = (PULONG64)Row;
	if (Row64[0] || Row64[1] || Row64[2] || Row64[3]) {
	    DbgPrint("%07x %04x %04x %04x %04x %04x %04x %04x %04x\n",
		     16*i, Row[0], Row[1], Row[2], Row[3],
		     Row[4], Row[5], Row[6], Row[7]);
	}
    }

    return STATUS_SUCCESS;
}
