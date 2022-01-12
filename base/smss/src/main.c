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

static NTSTATUS SmLoadBootDrivers()
{
    PCSTR DriversToLoad[] = {
	"\\BootModules\\null.sys",
	"\\BootModules\\beep.sys",
	"\\BootModules\\i8042prt.sys",
	"\\BootModules\\kbdclass.sys"
    };
    for (ULONG i = 0; i < ARRAY_LENGTH(DriversToLoad); i++) {
	SmPrint("Loading driver %s... ", DriversToLoad[i]);
	NTSTATUS Status = NtLoadDriverA(DriversToLoad[i]);
	if (NT_SUCCESS(Status)) {
	    SmPrint("OK\n");
	} else {
	    SmPrint("FAIL\n");
	}
    }
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

VOID SmTestBeepDriver(IN ULONG Freq,
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
    SmLoadBootDrivers();
    SmTestNullDriver();
    SmTestBeepDriver(440, 1000);

    if (!NT_SUCCESS(SmStartCommandPrompt())) {
	SmPrint("Failed to launch native command prompt. System halted.\n");
    }

    while (1);
}
