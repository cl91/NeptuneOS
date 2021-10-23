#include <nt.h>
#include <ntddbeep.h>
#include <stdarg.h>
#include <string.h>

PCSTR SMSS_BANNER = "\nNeptune OS Session Manager\n\n";

/* TODO: Move this to the CRT headers */
int _vsnprintf(char *buf, size_t size, const char *fmt, va_list args);

#define RET_ERR_EX(Expr, OnError)					\
    {NTSTATUS Status = (Expr); if (!NT_SUCCESS(Status)) {		\
	    DbgPrint("Expression %s in function %s @ %s:%d returned"	\
		     " error 0x%x\n",					\
		     #Expr, __func__, __FILE__, __LINE__, Status);	\
	    {OnError;} return Status; }}
#define RET_ERR(Expr)	RET_ERR_EX(Expr, {})

#define DECLARE_UNICODE_STRING(Name, Ptr, Length)			\
    UNICODE_STRING Name = { .Length = Length, .MaximumLength = Length,	\
	.Buffer = Ptr }

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
    PCSTR DriverToLoad = "\\BootModules\\null.sys";
    SmPrint("Loading driver %s... ", DriverToLoad);
    RET_ERR_EX(NtLoadDriverA(DriverToLoad),
	       SmPrint("FAILED\n"));
    SmPrint("OK\n");
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
    RtlInitUnicodeString(&BeepDevice, L"\\Device\\Beep");
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

NTAPI VOID NtProcessStartup(PPEB Peb)
{
    SmPrint(SMSS_BANNER);
    SmLoadBootDrivers();
    SmTestNullDriver();
    SmBeep(440, 1000);

    while (1);
}
