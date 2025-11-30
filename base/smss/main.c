#include "smss.h"
#include <mountmgr.h>

PCSTR SMSS_BANNER = "\nNeptune OS Session Manager [Version " VER_PRODUCTVERSION_STRING "]\n";

NTSTATUS SmPrint(PCSTR Format, ...)
{
    char buf[512];
    va_list arglist;
    va_start(arglist, Format);
    int n = _vsnprintf(buf, sizeof(buf), Format, arglist);
    va_end(arglist);
    if (n <= 0) {
	return STATUS_UNSUCCESSFUL;
    }
    NtDisplayStringA(buf);
    return STATUS_SUCCESS;
}

static NTSTATUS SmOpenKeyboard(IN PCWSTR ClassDeviceName,
			       OUT PHANDLE Keyboard,
			       OUT PHANDLE Event)
{
    UNICODE_STRING ClassDevice;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK Iosb;
    NTSTATUS Status;

    RtlInitUnicodeString(&ClassDevice, ClassDeviceName);
    InitializeObjectAttributes(&ObjectAttributes,
			       &ClassDevice, OBJ_CASE_INSENSITIVE, NULL, NULL);

    //
    // Open a handle to the keyboard class device
    //
    Status = NtCreateFile(Keyboard,
			  SYNCHRONIZE | GENERIC_READ | FILE_READ_ATTRIBUTES,
			  &ObjectAttributes, &Iosb,
			  NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN,
			  FILE_DIRECTORY_FILE, NULL, 0);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    //
    // Now create an event that will be used to wait on the device
    //
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    Status = NtCreateEvent(Event, EVENT_ALL_ACCESS, &ObjectAttributes, 1, 0);

    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS SmWaitForInput(IN HANDLE Keyboard,
			       IN HANDLE Event,
			       IN PVOID Buffer,
			       IN OUT PULONG BufferSize)
{
    IO_STATUS_BLOCK Iosb;
    LARGE_INTEGER ByteOffset;
    NTSTATUS Status;

    //
    // Clean up the I/O Status block and read from byte 0
    //
    RtlZeroMemory(&Iosb, sizeof(Iosb));
    RtlZeroMemory(&ByteOffset, sizeof(ByteOffset));

    //
    // Try to read the data
    //
    Status = NtReadFile(Keyboard, Event, NULL, NULL, &Iosb,
			Buffer, *BufferSize, &ByteOffset, NULL);

    //
    // Check if data is pending
    //
    if (Status == STATUS_PENDING) {
	//
	// Wait on the data to be read
	//
	Status = NtWaitForSingleObject(Event, TRUE, NULL);
    }

    //
    // Return status and how much data was read
    //
    *BufferSize = (ULONG) Iosb.Information;
    return Status;
}

static VOID SmGetKeyboardInput(IN HANDLE Keyboard,
			       IN HANDLE Event)
{
    KEYBOARD_INPUT_DATA KeyboardData[8];
    KBD_RECORD kbd_rec;
    ULONG BufferLength;

    while (TRUE) {
	BufferLength = sizeof(KeyboardData);
	NTSTATUS Status = SmWaitForInput(Keyboard, Event, &KeyboardData, &BufferLength);
	if (!NT_SUCCESS(Status)) {
	    SmPrint("\nUnable to read keyboard input. Status = 0x%x\n", Status);
	    break;
	};
	for (ULONG i = 0; i < BufferLength / sizeof(KEYBOARD_INPUT_DATA); i++) {
	    IntTranslateKey(&KeyboardData[i], &kbd_rec);
	    if (kbd_rec.bKeyDown) {
		CHAR c = kbd_rec.AsciiChar;
		SmPrint("%c", c);
	    }
	}
    }
}

static VOID SmMountDrives()
{
    NTSTATUS Status = SmLoadDriver("mountmgr");
    if (!NT_SUCCESS(Status)) {
	return;
    }
    SmPrint("Mounting drives...\n");
    UNICODE_STRING MountmgrDevice = RTL_CONSTANT_STRING(MOUNTMGR_DEVICE_NAME);
    OBJECT_ATTRIBUTES ObjAttr;
    InitializeObjectAttributes(&ObjAttr, &MountmgrDevice,
			       OBJ_CASE_INSENSITIVE, NULL, NULL);
    HANDLE MountmgrHandle = NULL;
    IO_STATUS_BLOCK IoStatus;
    Status = NtOpenFile(&MountmgrHandle, FILE_GENERIC_READ, &ObjAttr,
			&IoStatus, FILE_SHARE_READ | FILE_SHARE_WRITE,
			FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(Status)) {
	SmPrint("Failed to open mount manager device. Error = 0x%x\n", Status);
	return;
    }

    Status = NtDeviceIoControlFile(MountmgrHandle,
				   NULL, NULL, NULL, &IoStatus,
				   IOCTL_MOUNTMGR_AUTO_DL_ASSIGNMENTS,
				   NULL, 0, NULL, 0);
    if (!NT_SUCCESS(Status)) {
	SmPrint("Failed to assign drive letters. Error = 0x%x\n", Status);
	return;
    }

    BYTE Buffer[64 * 1024];    // 64 KB enough for typical systems
    RtlZeroMemory(Buffer, sizeof(Buffer));

    Status = NtDeviceIoControlFile(MountmgrHandle,
				   NULL, NULL, NULL,
				   &IoStatus,
				   IOCTL_MOUNTMGR_QUERY_POINTS,
				   Buffer, sizeof(Buffer),
				   Buffer, sizeof(Buffer));
    if (!NT_SUCCESS(Status)) {
	SmPrint("Failed to query mount points. Error = 0x%x\n", Status);
	return;
    }

    PMOUNTMGR_MOUNT_POINTS Mountpoints = (PMOUNTMGR_MOUNT_POINTS)Buffer;
    if (!Mountpoints->NumberOfMountPoints) {
	SmPrint("No drives mounted.\n");
	return;
    }

    for (ULONG i = 0; i < Mountpoints->NumberOfMountPoints; i++) {
	PMOUNTMGR_MOUNT_POINT Mountpoint = &Mountpoints->MountPoints[i];
	UNICODE_STRING SymbolicLink = {
	    .Buffer = (PUSHORT)&Buffer[Mountpoint->SymbolicLinkNameOffset],
	    .Length = Mountpoint->SymbolicLinkNameLength,
	    .MaximumLength = Mountpoint->SymbolicLinkNameLength
	};
	UNICODE_STRING DeviceName = {
	    .Buffer = (PUSHORT)&Buffer[Mountpoint->DeviceNameOffset],
	    .Length = Mountpoint->DeviceNameLength,
	    .MaximumLength = Mountpoint->DeviceNameLength
	};
	SmPrint("Mounted %wZ on %wZ\n", &DeviceName, &SymbolicLink);
    }
}

NTSTATUS SmStartCommandPrompt()
{
    PRTL_USER_PROCESS_PARAMETERS ProcessParams;
    RTL_USER_PROCESS_INFORMATION ProcessInfo = { 0 };
    WCHAR ProcessEnv[2] = { 0, 0 };

    UNICODE_STRING ImagePath;
    RtlInitUnicodeString(&ImagePath, L"\\??\\BootModules\\ntcmd.exe");

    NTSTATUS Status = RtlCreateProcessParameters(&ProcessParams, &ImagePath, NULL,
						 NULL, NULL, ProcessEnv, NULL, NULL,
						 NULL, NULL);
    if (!NT_SUCCESS(Status)) {
	SmPrint("RtlCreateProcessParameters failed with status 0x%x\n", Status);
	return STATUS_UNSUCCESSFUL;
    }

    Status = RtlCreateUserProcess(&ImagePath, OBJ_CASE_INSENSITIVE,
				  ProcessParams, NULL, NULL, NULL, FALSE,
				  NULL, NULL, &ProcessInfo);
    if (!NT_SUCCESS(Status)) {
	SmPrint("RtlCreateUserProcess failed with status 0x%x\n", Status);
	return STATUS_UNSUCCESSFUL;
    }

    Status = NtResumeThread(ProcessInfo.ThreadHandle, NULL);
    if (!NT_SUCCESS(Status)) {
	SmPrint("NtResumeThread failed with status 0x%x\n", Status);
	return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

static VOID SmCreateDosDevicesSymlink(IN PWSTR SymbolicLinkName)
{
    UNICODE_STRING SymbolicLinkNameU;
    RtlInitUnicodeString(&SymbolicLinkNameU, SymbolicLinkName);
    UNICODE_STRING PathName = RTL_CONSTANT_STRING(L"\\??");
    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, &SymbolicLinkNameU,
			       OBJ_PERMANENT | OBJ_CASE_INSENSITIVE,
			       NULL, NULL);
    HANDLE Handle;
    NTSTATUS Status = NtCreateSymbolicLinkObject(&Handle, SYMBOLIC_LINK_ALL_ACCESS,
						 &ObjectAttributes, &PathName);
    if (NT_SUCCESS(Status)) {
	NtClose(Handle);
    } else {
	SmPrint("Failed to create symbolic link %wZ. Error = 0x%x\n",
		&SymbolicLinkNameU, Status);
    }
}

NTAPI VOID NtProcessStartup(PPEB Peb)
{
    SmPrint("%s\n", SMSS_BANNER);
    SmCreateDosDevicesSymlink(L"\\DosDevices");
    SmCreateDosDevicesSymlink(L"\\GLOBAL??");
    SmInitRegistry();
    SmInitHardwareDatabase();
    SmMountDrives();
    SmPrint("\n");

    if (!NT_SUCCESS(SmStartCommandPrompt())) {
	SmPrint("Failed to launch native command prompt. System halted.\n");
    }

    while (1);
}
