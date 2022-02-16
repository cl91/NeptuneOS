#include <smss.h>
#include <ntddbeep.h>

PCSTR SMSS_BANNER = "\nNeptune OS Session Manager\n";

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

/*
 * Call the beep.sys driver to make a beep of given frequency (in Hz)
 * and duration (in ms)
 *
 * Returns true if beep is successful
 */
static BOOLEAN SmBeep(IN ULONG dwFreq,
		      IN ULONG dwDuration)
{
    HANDLE hBeep;
    UNICODE_STRING BeepDevice;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;

    /* Open the device */
    RtlInitUnicodeString(&BeepDevice, DD_BEEP_DEVICE_NAME_U);
    InitializeObjectAttributes(&ObjectAttributes, &BeepDevice, 0, NULL, NULL);
    NTSTATUS Status = NtCreateFile(&hBeep, FILE_READ_DATA | FILE_WRITE_DATA,
				   &ObjectAttributes, &IoStatusBlock, NULL, 0,
				   FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
				   0, NULL, 0);
    if (!NT_SUCCESS(Status)) {
	return FALSE;
    }

    /* check the parameters */
    if ((dwFreq >= 0x25 && dwFreq <= 0x7FFF) || (dwFreq == 0x0 && dwDuration == 0x0)) {
	BEEP_SET_PARAMETERS BeepSetParameters;
	/* Set beep data */
	BeepSetParameters.Frequency = dwFreq;
	BeepSetParameters.Duration = dwDuration;

	/* Send the beep */
	Status = NtDeviceIoControlFile(hBeep, NULL, NULL, NULL, &IoStatusBlock,
				       IOCTL_BEEP_SET, &BeepSetParameters,
				       sizeof(BeepSetParameters), NULL, 0);
    } else {
	Status = STATUS_INVALID_PARAMETER;
    }

    NtClose(hBeep);
    return NT_SUCCESS(Status);
}

static NTSTATUS SmTestNullDriver()
{
    HANDLE hNull;
    UNICODE_STRING NullDevice;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;

    /* Open the device */
    RtlInitUnicodeString(&NullDevice, L"\\Device\\Null");
    InitializeObjectAttributes(&ObjectAttributes, &NullDevice, 0, NULL, NULL);
    RET_ERR_EX(NtCreateFile(&hNull, FILE_READ_DATA | FILE_WRITE_DATA,
			    &ObjectAttributes, &IoStatusBlock, NULL, 0,
			    FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
			    0, NULL, 0),
	       SmPrint("Failed to create device handle for null.sys. Status = 0x%x\n", Status));

    return STATUS_SUCCESS;
}

static VOID SmTestBeepDriver(IN ULONG Freq,
			     IN ULONG Duration)
{
    SmPrint("Testing beep driver with frequency %d Hz duration %d ms...\n",
	    Freq, Duration);
    BOOLEAN BeepSuccess = SmBeep(Freq, Duration);
    if (BeepSuccess) {
	SmPrint("Success. You should hear a beep.\n\n");
    } else {
	SmPrint("FAILED.\n\n");
    }
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
	SmWaitForInput(Keyboard, Event, &KeyboardData, &BufferLength);
	for (ULONG i = 0; i < BufferLength / sizeof(KEYBOARD_INPUT_DATA); i++) {
	    IntTranslateKey(&KeyboardData[i], &kbd_rec);
	    if (kbd_rec.bKeyDown) {
		CHAR c = kbd_rec.AsciiChar;
		SmPrint("%c", c);
	    }
	}
    }
}

NTSTATUS SmStartCommandPrompt()
{
    PRTL_USER_PROCESS_PARAMETERS ProcessParams;
    RTL_USER_PROCESS_INFORMATION ProcessInfo = { 0 };
    WCHAR ProcessEnv[2] = { 0, 0 };

    UNICODE_STRING ImagePath;
    RtlInitUnicodeString(&ImagePath, L"\\BootModules\\ntcmd.exe");

    NTSTATUS Status = RtlCreateProcessParameters(&ProcessParams, &ImagePath, NULL,
						 NULL, NULL, ProcessEnv, NULL, NULL,
						 NULL, NULL);
    if (!NT_SUCCESS(Status)) {
	SmPrint("RtlCreateProcessParameters failed\n");
	return STATUS_UNSUCCESSFUL;
    }

    Status = RtlCreateUserProcess(&ImagePath, OBJ_CASE_INSENSITIVE,
				  ProcessParams, NULL, NULL, NULL, FALSE,
				  NULL, NULL, &ProcessInfo);
    if (!NT_SUCCESS(Status)) {
	SmPrint("RtlCreateUserProcess failed\n");
	return STATUS_UNSUCCESSFUL;
    }

    Status = NtResumeThread(ProcessInfo.ThreadHandle, NULL);
    if (!NT_SUCCESS(Status)) {
	SmPrint("NtResumeThread failed\n");
	return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

NTAPI VOID NtProcessStartup(PPEB Peb)
{
    SmPrint("%s\n", SMSS_BANNER);
    SmInitRegistry();
    SmInitHardwareDatabase();
    SmTestNullDriver();
    SmTestBeepDriver(440, 1000);

    PCWSTR ClassDeviceName = L"\\Device\\KeyboardClass0";
    HANDLE Keyboard = NULL;
    HANDLE Event = NULL;
    NTSTATUS Status = SmOpenKeyboard(ClassDeviceName, &Keyboard, &Event);
    if (!NT_SUCCESS(Status)) {
	SmPrint("Unable to open %ws. Status = 0x%x\n",
		ClassDeviceName, Status);
	goto out;
    }
    assert(Keyboard != NULL);
    assert(Event != NULL);

    SmPrint("Reading keyboard input...\n");
    SmGetKeyboardInput(Keyboard, Event);

out:
    if (!NT_SUCCESS(SmStartCommandPrompt())) {
	SmPrint("Failed to launch native command prompt. System halted.\n");
    }

    while (1);
}
