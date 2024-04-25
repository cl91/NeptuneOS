#include "ntdef.h"
#include "ntobapi.h"
#include <smss.h>

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
    SmPrint("Mounting drive A... ");
    UNICODE_STRING FloppyDevice = RTL_CONSTANT_STRING(L"\\Device\\Floppy0");
    UNICODE_STRING FloppyDosDevice = RTL_CONSTANT_STRING(L"\\??\\A:");
    OBJECT_ATTRIBUTES ObjAttr;
    InitializeObjectAttributes(&ObjAttr, &FloppyDosDevice, 0, NULL, NULL);
    HANDLE Symlink = NULL;
    NTSTATUS Status = NtCreateSymbolicLinkObject(&Symlink, SYMBOLIC_LINK_ALL_ACCESS,
						 &ObjAttr, &FloppyDevice);
    if (!NT_SUCCESS(Status)) {
	SmPrint("Failed to create symbolic link for drive A (error 0x%08x).\n", Status);
	return;
    }
    NtClose(Symlink);
    UNICODE_STRING DriveA = RTL_CONSTANT_STRING(L"A:\\");
    Status = RtlSetCurrentDirectory_U(&DriveA);
    if (!NT_SUCCESS(Status)) {
	SmPrint("Failed to mount drive A (error 0x%08x).\n", Status);
	return;
    }
    SmPrint("OK\n");
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

NTAPI VOID NtProcessStartup(PPEB Peb)
{
    SmPrint("%s\n", SMSS_BANNER);
    SmInitRegistry();
    SmInitHardwareDatabase();
    SmMountDrives();
    SmPrint("\n");

    if (!NT_SUCCESS(SmStartCommandPrompt())) {
	SmPrint("Failed to launch native command prompt. System halted.\n");
    }

    while (1);
}
