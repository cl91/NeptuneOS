#include "umtests.h"
#include <ntddbeep.h>

/*
 * Call the beep.sys driver to make a beep of given frequency (in Hz)
 * and duration (in ms)
 *
 * Returns true if beep is successful
 */
static BOOLEAN Beep(IN ULONG dwFreq,
		    IN ULONG dwDuration)
{
    /* The beep driver will stop the beep as soon as we close the handle.
     * Since we don't want to set up a timer to close the handle after the
     * beep timeout we will intentionally leak the handle and never close it. */
    static HANDLE hBeep;
    UNICODE_STRING BeepDevice;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    NTSTATUS Status = STATUS_SUCCESS;

    /* Open the device */
    if (!hBeep) {
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

    return NT_SUCCESS(Status);
}

NTSTATUS TestNullDriver()
{
    HANDLE hNull;
    UNICODE_STRING NullDevice;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;

    /* Open the device */
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
    VgaPrint("Testing beep driver with frequency %d Hz duration %d ms...\n",
	     Freq, Duration);
    BOOLEAN BeepSuccess = Beep(Freq, Duration);
    if (BeepSuccess) {
	VgaPrint("Success. You should hear a beep.\n");
    } else {
	VgaPrint("FAILED.\n");
    }
}
