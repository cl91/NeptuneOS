#include "umtests.h"
#include <ntddbeep.h>

#define SYSTEM_KEY_PATH				"\\Registry\\Machine\\System"
#define CURRENT_CONTROL_SET_KEY_PATH		SYSTEM_KEY_PATH "\\CurrentControlSet"
#define SERVICE_KEY_PATH			CURRENT_CONTROL_SET_KEY_PATH "\\Services"

static NTSTATUS LoadDriver(IN PCSTR DriverToLoad)
{
    CHAR ServiceFullPath[512];
    snprintf(ServiceFullPath, sizeof(ServiceFullPath),
	     SERVICE_KEY_PATH "\\%s", DriverToLoad);
    VgaPrint("Loading driver %s... ", ServiceFullPath);
    NTSTATUS Status = NtLoadDriverA(ServiceFullPath);
    if (!NT_SUCCESS(Status)) {
	VgaPrint("FAIL (0x%x)\n", Status);
    } else {
	VgaPrint("OK\n");
    }
    return Status;
}

/*
 * Call the beep.sys driver to make a beep of given frequency (in Hz)
 * and duration (in ms)
 *
 * Returns true if beep is successful
 */
static BOOLEAN Beep(IN ULONG dwFreq,
		    IN ULONG dwDuration)
{
    HANDLE hBeep;
    UNICODE_STRING BeepDevice;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    NTSTATUS Status = STATUS_SUCCESS;

    /* Open the device */
    RtlInitUnicodeString(&BeepDevice, DD_BEEP_DEVICE_NAME_U);
    InitializeObjectAttributes(&ObjectAttributes, &BeepDevice, 0, NULL, NULL);
    Status = NtCreateFile(&hBeep, FILE_READ_DATA | FILE_WRITE_DATA,
			  &ObjectAttributes, &IoStatusBlock, NULL, 0,
			  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
			  0, NULL, 0);
    if (!NT_SUCCESS(Status)) {
	DbgTrace("NtCreateFile returned error status 0x%x\n", Status);
	return FALSE;
    }

    /* Check the parameters */
    if ((dwFreq >= 0x25 && dwFreq <= 0x7FFF) || (dwFreq == 0x0 && dwDuration == 0x0)) {
	BEEP_SET_PARAMETERS BeepSetParameters;
	/* Set beep data */
	BeepSetParameters.Frequency = dwFreq;
	BeepSetParameters.Duration = dwDuration;

	/* Send the beep */
	Status = NtDeviceIoControlFile(hBeep, NULL, NULL, NULL, &IoStatusBlock,
				       IOCTL_BEEP_SET, &BeepSetParameters,
				       sizeof(BeepSetParameters), NULL, 0);
	if (!NT_SUCCESS(Status)) {
	    DbgTrace("NtDeviceIoControlFile returned error status 0x%x\n",
		     Status);
	}
    } else {
	DbgTrace("Invalid beep parameter freq %d duration %d\n",
		 dwFreq, dwDuration);
	Status = STATUS_INVALID_PARAMETER;
    }
    NtClose(hBeep);

    return NT_SUCCESS(Status);
}

NTSTATUS TestNullDriver()
{
    HANDLE hNull;
    UNICODE_STRING NullDevice;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;

    /* Open the device */
    LoadDriver("null");
    RtlInitUnicodeString(&NullDevice, L"\\Device\\Null");
    InitializeObjectAttributes(&ObjectAttributes, &NullDevice, 0, NULL, NULL);
    NTSTATUS Status = NtCreateFile(&hNull, FILE_READ_DATA | FILE_WRITE_DATA,
				   &ObjectAttributes, &IoStatusBlock, NULL, 0,
				   FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
				   0, NULL, 0);
    if (!NT_SUCCESS(Status)) {
	VgaPrint("Failed to create device handle for null.sys. Status = 0x%x\n", Status);
	return Status;
    }

    return STATUS_SUCCESS;
}

VOID TestBeepDriver(IN ULONG Freq,
		    IN ULONG Duration)
{
    LoadDriver("beep");
    VgaPrint("Testing beep driver with frequency %d Hz duration %d ms...\n",
	     Freq, Duration);
    BOOLEAN BeepSuccess = Beep(Freq, Duration);
    if (BeepSuccess) {
	VgaPrint("Success. You should hear a beep.\n");
    } else {
	VgaPrint("FAILED.\n");
    }
}

VOID TestMemDriver()
{
    LoadDriver("mem");
    HANDLE FileHandle;
    UNICODE_STRING NullDevice;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    RtlInitUnicodeString(&NullDevice, L"\\Device\\LnxDrv\\zero");
    InitializeObjectAttributes(&ObjectAttributes, &NullDevice, 0, NULL, NULL);
    NTSTATUS Status = NtCreateFile(&FileHandle, FILE_READ_DATA | FILE_WRITE_DATA,
				   &ObjectAttributes, &IoStatusBlock, NULL, 0,
				   FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
				   0, NULL, 0);
    if (!NT_SUCCESS(Status)) {
	VgaPrint("Failed to create device handle. Status = 0x%x\n", Status);
	return;
    }

    CHAR Buffer[64];
    memset(Buffer, 0xff, sizeof(Buffer));
    VgaPrint("Before reading zero file:");
    for (ULONG i = 0; i < sizeof(Buffer); i++) {
	if (!(i % 16)) {
	    VgaPrint("\n");
	}
	VgaPrint("%d ", Buffer[i]);
    }
    VgaPrint("\n");
    LARGE_INTEGER FileOffset = {};
    Status = NtReadFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock,
			Buffer, sizeof(Buffer), &FileOffset, NULL);
    if (!NT_SUCCESS(Status)) {
	VgaPrint("Failed to read device file. Status = 0x%x\n", Status);
    } else {
	VgaPrint("After reading zero file:");
	for (ULONG i = 0; i < sizeof(Buffer); i++) {
	    if (!(i % 16)) {
		VgaPrint("\n");
	    }
	    VgaPrint("%d ", Buffer[i]);
	}
	VgaPrint("\n");
    }
}

static VOID SendReceivePackets(IN PWSTR DevicePath)
{
    HANDLE FileHandle;
    UNICODE_STRING EthDevice;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    RtlInitUnicodeString(&EthDevice, DevicePath);
    InitializeObjectAttributes(&ObjectAttributes, &EthDevice, 0, NULL, NULL);
    NTSTATUS Status = NtCreateFile(&FileHandle, FILE_READ_DATA | FILE_WRITE_DATA,
				   &ObjectAttributes, &IoStatusBlock, NULL, 0,
				   FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
				   0, NULL, 0);
    if (!NT_SUCCESS(Status)) {
	VgaPrint("Failed to create device handle. Status = 0x%x\n", Status);
	return;
    }

    VgaPrint("Trying to receive a packet\n");
    UCHAR Buffer[512] = {};
    LARGE_INTEGER FileOffset = {};
    Status = NtReadFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock,
			Buffer, sizeof(Buffer), &FileOffset, NULL);
    if (!NT_SUCCESS(Status)) {
	VgaPrint("Failed to read device file. Status = 0x%x\n", Status);
    }
    for (ULONG i = 0; i < min(sizeof(Buffer), 64); i++) {
	if (i && !(i % 16)) {
	    VgaPrint("\n");
	}
	VgaPrint("%02x ", Buffer[i]);
    }
    VgaPrint("\n");

    VgaPrint("Trying to send a packet\n");
    UCHAR Packet[] = {
	// --- Ethernet header (14 bytes) ---
	0xff,0xff,0xff,0xff,0xff,0xff,        // dest: broadcast
	0x52,0x54,0x00,0x12,0x34,0x56,        // src: your MAC
	0x08,0x06,                            // ethertype: ARP

	// --- ARP header (28 bytes) ---
	0x00,0x01,    // hardware type: Ethernet
	0x08,0x00,    // protocol type: IPv4
	0x06,         // hardware size
	0x04,         // protocol size
	0x00,0x01,    // opcode: request

	// sender MAC (same as src)
	0x52,0x54,0x00,0x12,0x34,0x56,

	// sender IP: 192.168.0.2
	0xc0,0xa8,0x00,0x02,

	// target MAC: unknown
	0x00,0x00,0x00,0x00,0x00,0x00,

	// target IP: 192.168.0.1
	0xc0,0xa8,0x00,0x01,
    };
    RtlZeroMemory(Buffer, sizeof(Buffer));
    RtlCopyMemory(Buffer, Packet, sizeof(Packet));
    Status = NtWriteFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock,
			 Buffer, sizeof(Buffer), &FileOffset, NULL);
    if (!NT_SUCCESS(Status)) {
	VgaPrint("Failed to write device file. Status = 0x%x\n", Status);
    }
    NtClose(FileHandle);
}

VOID TestEthernetDriver()
{
    NTSTATUS Status;
    HANDLE DirectoryHandle = NULL;
    UNICODE_STRING DirName;
    OBJECT_ATTRIBUTES ObjectAttributes;
    PVOID QueryBuffer = NULL;
    ULONG BufferSize = 4096;
    ULONG Context = 0;
    ULONG ReturnLength = 0;
    BOOLEAN RestartScan = TRUE;

    RtlInitUnicodeString(&DirName, L"\\Device\\LnxDrv");
    InitializeObjectAttributes(&ObjectAttributes, &DirName,
			       OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    /* Open the object directory */
    Status = NtOpenDirectoryObject(&DirectoryHandle, DIRECTORY_QUERY, &ObjectAttributes);
    if (!NT_SUCCESS(Status)) {
	VgaPrint("Failed to open directory object. Status: 0x%08X\n", Status);
	return;
    }

    /* Allocate memory for the directory entries */
    QueryBuffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, BufferSize);
    if (QueryBuffer == NULL) {
	Status = STATUS_INSUFFICIENT_RESOURCES;
	goto Cleanup;
    }

    /*
     * Lists and filters device objects containing ":eth" under \Device\LnxDrv.
     */
    while (TRUE) {
	Status = NtQueryDirectoryObject(DirectoryHandle, QueryBuffer, BufferSize,
					FALSE, RestartScan, &Context, &ReturnLength);

	if (Status == STATUS_NO_MORE_ENTRIES) {
	    Status = STATUS_SUCCESS;
	    break;
	}

	if (!NT_SUCCESS(Status)) {
	    VgaPrint("Directory query failed. Status: 0x%08X\n", Status);
	    break;
	}

	POBJECT_DIRECTORY_INFORMATION DirInfo = QueryBuffer;
	PCHAR BufEnd = (PCHAR)QueryBuffer + ReturnLength;

	/* Iterate through the returned batch of entries */
	while (DirInfo->Name.Buffer != NULL && DirInfo->TypeName.Buffer != NULL) {
	    VgaPrint("Found object %wZ of type %wZ\n", &DirInfo->Name, &DirInfo->TypeName);
	    UNICODE_STRING TargetType = RTL_CONSTANT_STRING(L"Device");

	    /* Check if the object type is "Device" */
	    if (RtlEqualUnicodeString(&DirInfo->TypeName, &TargetType, TRUE)) {
		/* Filter for names containing ":eth" */
		if (wcsstr(DirInfo->Name.Buffer, L":eth") != NULL ||
		    wcsstr(DirInfo->Name.Buffer, L":ETH") != NULL) {
		    WCHAR DevicePath[512];
		    _snwprintf(DevicePath, ARRAYSIZE(DevicePath), L"%wZ\\%wZ",
			       &DirName, &DirInfo->Name);
		    SendReceivePackets(DevicePath);
		}
	    }

	    if (((PCHAR)DirInfo->Name.Buffer + DirInfo->Name.MaximumLength >= BufEnd) ||
		((PCHAR)DirInfo->TypeName.Buffer + DirInfo->TypeName.MaximumLength >= BufEnd)) {
		break;
	    }

	    DirInfo++; /* Move to the next entry in the buffer */
	}

	RestartScan = FALSE; /* Continue from where we left off in the next iteration */
    }

Cleanup:
    if (QueryBuffer != NULL) {
	RtlFreeHeap(RtlGetProcessHeap(), 0, QueryBuffer);
    }
    if (DirectoryHandle != NULL) {
	NtClose(DirectoryHandle);
    }
}
