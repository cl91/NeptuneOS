/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS kernel
 * FILE:            ntoskrnl/io/iomgr/iorsrce.c
 * PURPOSE:         Hardware resource managment
 *
 * PROGRAMMERS:     David Welch (welch@mcmail.com)
 *                  Alex Ionescu (alex@relsoft.net)
 *                  Pierre Schweitzer (pierre.schweitzer@reactos.org)
 */

/* INCLUDES *****************************************************************/

#include <wdmp.h>

/* MACROS *******************************************************************/

#define TAG_IO_RESOURCE        'CRSR'
#define DEVICE_DESCRIPTION_KEY L"\\REGISTRY\\MACHINE\\HARDWARE\\DESCRIPTION\\SYSTEM"

/* GLOBALS *******************************************************************/

static CONFIGURATION_INFORMATION _SystemConfigurationInformation = {
    0, 0, 0, 0, 0, 0, 0, FALSE, FALSE, 0, 0
};

/* API Parameters to Pass in IopQueryBusDescription */
typedef struct IO_QUERY {
    PINTERFACE_TYPE BusType;
    PULONG BusNumber;
    PCONFIGURATION_TYPE ControllerType;
    PULONG ControllerNumber;
    PCONFIGURATION_TYPE PeripheralType;
    PULONG PeripheralNumber;
    PIO_QUERY_DEVICE_ROUTINE CalloutRoutine;
    PVOID Context;
} IO_QUERY, *PIO_QUERY;

static PWSTR ArcTypes[] = {
    L"System",
    L"CentralProcessor",
    L"FloatingPointProcessor",
    L"PrimaryICache",
    L"PrimaryDCache",
    L"SecondaryICache",
    L"SecondaryDCache",
    L"SecondaryCache",
    L"EisaAdapter",
    L"TcAdapter",
    L"ScsiAdapter",
    L"DtiAdapter",
    L"MultifunctionAdapter",
    L"DiskController",
    L"TapeController",
    L"CdRomController",
    L"WormController",
    L"SerialController",
    L"NetworkController",
    L"DisplayController",
    L"ParallelController",
    L"PointerController",
    L"KeyboardController",
    L"AudioController",
    L"OtherController",
    L"DiskPeripheral",
    L"FloppyDiskPeripheral",
    L"TapePeripheral",
    L"ModemPeripheral",
    L"MonitorPeripheral",
    L"PrinterPeripheral",
    L"PointerPeripheral",
    L"KeyboardPeripheral",
    L"TerminalPeripheral",
    L"OtherPeripheral",
    L"LinePeripheral",
    L"NetworkPeripheral",
    L"SystemMemory",
    L"DockingInformation",
    L"RealModeIrqRoutingTable",
    L"RealModePCIEnumeration",
    L"Undefined"
};

/* PRIVATE FUNCTIONS **********************************************************/

static NTSTATUS IopCreateRegistryKeyEx(OUT PHANDLE Handle,
				       IN OPTIONAL HANDLE RootHandle,
				       IN PUNICODE_STRING KeyName,
				       IN ACCESS_MASK DesiredAccess,
				       IN ULONG CreateOptions,
				       OUT OPTIONAL PULONG Disposition)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    ULONG KeyDisposition, RootHandleIndex = 0, i = 1, NestedCloseLevel = 0;
    USHORT Length;
    HANDLE HandleArray[2];
    BOOLEAN Recursing = TRUE;
    PWCHAR pp, p, p1;
    UNICODE_STRING KeyString;
    NTSTATUS Status = STATUS_SUCCESS;
    PAGED_CODE();

    /* P1 is start, pp is end */
    p1 = KeyName->Buffer;
    pp = (PVOID)((ULONG_PTR)p1 + KeyName->Length);

    /* Create the target key */
    InitializeObjectAttributes(&ObjectAttributes, KeyName,
			       OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, RootHandle,
			       NULL);
    Status = NtCreateKey(&HandleArray[i], DesiredAccess, &ObjectAttributes, 0, NULL,
			 CreateOptions, &KeyDisposition);

    /* Now we check if this failed */
    if ((Status == STATUS_OBJECT_NAME_NOT_FOUND) && (RootHandle)) {
	/* Target key failed, so we'll need to create its parent. Setup array */
	HandleArray[0] = NULL;
	HandleArray[1] = RootHandle;

	/* Keep recursing for each missing parent */
	while (Recursing) {
	    /* And if we're deep enough, close the last handle */
	    if (NestedCloseLevel > 1)
		NtClose(HandleArray[RootHandleIndex]);

	    /* We're setup to ping-pong between the two handle array entries */
	    RootHandleIndex = i;
	    i = (i + 1) & 1;

	    /* Clear the one we're attempting to open now */
	    HandleArray[i] = NULL;

	    /* Process the parent key name */
	    for (p = p1; ((p < pp) && (*p != OBJ_NAME_PATH_SEPARATOR)); p++)
		;
	    Length = (USHORT)(p - p1) * sizeof(WCHAR);

	    /* Is there a parent name? */
	    if (Length) {
		/* Build the unicode string for it */
		KeyString.Buffer = p1;
		KeyString.Length = KeyString.MaximumLength = Length;

		/* Now try opening the parent */
		InitializeObjectAttributes(&ObjectAttributes, &KeyString,
					   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
					   HandleArray[RootHandleIndex], NULL);
		Status = NtCreateKey(&HandleArray[i], DesiredAccess, &ObjectAttributes, 0,
				     NULL, CreateOptions, &KeyDisposition);
		if (NT_SUCCESS(Status)) {
		    /* It worked, we have one more handle */
		    NestedCloseLevel++;
		} else {
		    /* Parent key creation failed, abandon loop */
		    Recursing = FALSE;
		    continue;
		}
	    } else {
		/* We don't have a parent name, probably corrupted key name */
		Status = STATUS_INVALID_PARAMETER;
		Recursing = FALSE;
		continue;
	    }

	    /* Now see if there's more parents to create */
	    p1 = p + 1;
	    if ((p == pp) || (p1 == pp)) {
		/* We're done, hopefully successfully, so stop */
		Recursing = FALSE;
	    }
	}

	/* Outer loop check for handle nesting that requires closing the top handle */
	if (NestedCloseLevel > 1)
	    NtClose(HandleArray[RootHandleIndex]);
    }

    /* Check if we broke out of the loop due to success */
    if (NT_SUCCESS(Status)) {
	/* Return the target handle (we closed all the parent ones) and disposition */
	*Handle = HandleArray[i];
	if (Disposition)
	    *Disposition = KeyDisposition;
    }

    /* Return the success state */
    return Status;
}

/*
 * Append "\\%d" to the given unicode string, where %d is the given integer.
 */
static NTSTATUS IopAppendIntegerSubKey(OUT PUNICODE_STRING String,
				       IN ULONG Integer)
{
    WCHAR TempBuffer[16];
    UNICODE_STRING TempString = {
	.MaximumLength = sizeof(TempBuffer),
	.Length = 0,
	.Buffer = TempBuffer
    };

    RET_ERR(RtlIntegerToUnicodeString(Integer, 10, &TempString));

    RET_ERR(RtlAppendUnicodeToString(String, L"\\"));
    RET_ERR(RtlAppendUnicodeStringToString(String, &TempString));

    return STATUS_SUCCESS;
}

/*
 * Append "\\ArcType[Type]" for the specified configuration type
 */
static NTSTATUS IopAppendArcTypeSubKey(OUT PUNICODE_STRING String,
				       IN CONFIGURATION_TYPE Type)
{
    assert(Type < ARRAYSIZE(ArcTypes));
    RET_ERR(RtlAppendUnicodeToString(String, L"\\"));
    RET_ERR(RtlAppendUnicodeToString(String, ArcTypes[Type]));
    return STATUS_SUCCESS;
}

/*
 * Query the registry and find out how many subkeys the given key has
 */
static NTSTATUS IopGetSubKeyCount(IN UNICODE_STRING Key,
				  OUT ULONG *SubKeyCount)
{
    assert(SubKeyCount != NULL);

    HANDLE KeyHandle = NULL;
    RET_ERR(IopOpenKey(Key, &KeyHandle));

    /* Find out how much buffer space we should allocate */
    PKEY_FULL_INFORMATION FullInfo = NULL;
    ULONG LenFullInfo = 0;
    NTSTATUS Status = NtQueryKey(KeyHandle, KeyFullInformation, NULL, 0, &LenFullInfo);
    if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_TOO_SMALL &&
	Status != STATUS_BUFFER_OVERFLOW) {
	goto out;
    }
    assert(LenFullInfo != 0);

    /* Allocate the key information buffer */
    FullInfo = ExAllocatePoolWithTag(NonPagedPool, LenFullInfo, TAG_IO_RESOURCE);
    if (FullInfo == NULL) {
	Status = STATUS_NO_MEMORY;
	goto out;
    }

    /* Get the Key Full Information */
    Status = NtQueryKey(KeyHandle, KeyFullInformation,
			FullInfo, LenFullInfo, &LenFullInfo);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }

    *SubKeyCount= FullInfo->SubKeys;

out:
    assert(KeyHandle != NULL);
    NtClose(KeyHandle);
    if (FullInfo != NULL) {
	ExFreePoolWithTag(FullInfo, TAG_IO_RESOURCE);
    }
    return Status;
}

/*
 * If the caller has specified the controller/peripheral number,
 * use it. Otherwise, read the subkey count from the registry.
 */
static NTSTATUS IopGetConfigurationCount(IN PULONG SpecifiedNumber,
					 IN UNICODE_STRING ConfigKey,
					 OUT ULONG *Number,
					 OUT ULONG *MaxNumber)
{
    if (SpecifiedNumber && *SpecifiedNumber) {
	*Number = *SpecifiedNumber;
	*MaxNumber = *Number + 1;
    } else {
	*Number = 0;
	RET_ERR(IopGetSubKeyCount(ConfigKey, MaxNumber));
    }
    return STATUS_SUCCESS;
}

static PWSTR ConfigurationValueNames[] = {
    L"Identifier",
    L"Configuration Data",
    L"Component Information"
};

/*
 * Free the configuration information allocated previously. Information must
 * have exactly three elements. The Information array itself is not freed.
 */
static VOID IopFreeConfigurationInformation(IN PKEY_VALUE_FULL_INFORMATION *Information)
{
    for (ULONG i = 0; i < ARRAYSIZE(ConfigurationValueNames); i++) {
	if (Information[i] != NULL) {
	    ExFreePoolWithTag(Information[i], TAG_IO_RESOURCE);
	}
    }
}

/*
 * Read the configuration data for the given controller/peripheral.
 *
 * The Information array must have exactly three elements and must be zero initialized.
 */
static NTSTATUS IopGetConfigurationInformation(IN UNICODE_STRING RegKey,
					       OUT PKEY_VALUE_FULL_INFORMATION *Information)
{
    assert(Information != NULL);
    assert(Information[0] == NULL);
    assert(Information[1] == NULL);
    assert(Information[2] == NULL);

    HANDLE KeyHandle = NULL;
    RET_ERR(IopOpenKey(RegKey, &KeyHandle));
    assert(KeyHandle != NULL);

    /* Read the configuration data from registry */
    NTSTATUS Status = STATUS_SUCCESS;
    for (ULONG i = 0; i < ARRAYSIZE(ConfigurationValueNames); i++) {
	UNICODE_STRING ValueString;
	RtlInitUnicodeString(&ValueString, ConfigurationValueNames[i]);

	/* Find out how much buffer space we need */
	ULONG BufferSize = 0;
	Status = NtQueryValueKey(KeyHandle, &ValueString,
				 KeyValueFullInformation, NULL, 0,
				 &BufferSize);
	/* If we get an error, simply continue looking at the next
	 * information data. Information[i] will be left as NULL. */
	if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_TOO_SMALL &&
	    Status != STATUS_BUFFER_OVERFLOW) {
	    Status = STATUS_SUCCESS;
	    continue;
	}
	assert(BufferSize != 0);

	/* Allocate the required buffer space */
	Information[i] = ExAllocatePoolWithTag(NonPagedPool, BufferSize,
					       TAG_IO_RESOURCE);
	if (Information[i] == NULL) {
	    Status = STATUS_NO_MEMORY;
	    goto out;
	}

	/* Get the configuration information */
	Status = NtQueryValueKey(KeyHandle, &ValueString,
				 KeyValueFullInformation,
				 Information[i],
				 BufferSize,
				 &BufferSize);
	/* We should never get these errors because we asked for the
	 * correct buffer size before. */
	assert(Status != STATUS_BUFFER_TOO_SMALL);
	assert(Status != STATUS_BUFFER_OVERFLOW);
	/* We ignore the error above and simply continue */
    }

    /* If we got here, everything went well */
    Status = STATUS_SUCCESS;

out:
    if (!NT_SUCCESS(Status)) {
	IopFreeConfigurationInformation(Information);
    }
    assert(KeyHandle != NULL);
    NtClose(KeyHandle);
    return Status;
}

/*
 * IopQueryDeviceDescription
 *
 * FUNCTION:
 *     Reads and returns Hardware information from the appropriate hardware
 *     registry key. Helper sub-routine of IopQueryBusDescription.
 *
 * ARGUMENTS:
 *     Query          - What the parent function wants.
 *     RootKey        - Which key to look in
 *     Bus            - Bus Number.
 *     BusInformation - The Configuration Information Sent
 *
 * RETURNS:
 *     Status
 */
static NTSTATUS IopQueryDeviceDescription(IN PIO_QUERY Query,
					  IN UNICODE_STRING RootKey,
					  IN ULONG Bus,
					  IN PKEY_VALUE_FULL_INFORMATION *BusInformation)
{
    assert(Query != NULL);
    assert(Query->ControllerType != NULL);

    /* Add Controller Name to String */
    UNICODE_STRING ControllerRootKey = RootKey;
    RET_ERR(IopAppendArcTypeSubKey(&ControllerRootKey,
				   *Query->ControllerType));

    /* Get the number of controllers */
    ULONG ControllerNumber;
    ULONG MaximumControllerNumber;
    RET_ERR(IopGetConfigurationCount(Query->ControllerNumber,
				     ControllerRootKey,
				     &ControllerNumber,
				     &MaximumControllerNumber));

    /* Loop through controllers */
    for (; ControllerNumber < MaximumControllerNumber; ControllerNumber++) {
	/* Append the controller number subkey to the root controller key */
	UNICODE_STRING RegKey = ControllerRootKey;
	RET_ERR(IopAppendIntegerSubKey(&RegKey, ControllerNumber));

	PKEY_VALUE_FULL_INFORMATION ControllerInformation[] = { NULL, NULL, NULL };
	RET_ERR(IopGetConfigurationInformation(RegKey, ControllerInformation));

	NTSTATUS Status = STATUS_SUCCESS;
	/* We now have Bus and Controller Information. If caller did not
	 * supply a peripheral type, call the callback routine and get out. */
	if (!Query->PeripheralType || !(*Query->PeripheralType)) {
	    Status = Query->CalloutRoutine(Query->Context,
					   &RegKey,
					   *Query->BusType,
					   Bus,
					   BusInformation,
					   *Query->ControllerType,
					   ControllerNumber,
					   ControllerInformation,
					   0,
					   0,
					   NULL);
	    goto cleanup;
	}

	/* Otherwise, continue querying the peripheral keys. */
	IF_ERR_GOTO(cleanup, Status,
		    IopAppendArcTypeSubKey(&RegKey, *Query->PeripheralType));

	ULONG PeripheralNumber;
	ULONG MaximumPeripheralNumber;
	IF_ERR_GOTO(cleanup, Status,
		    IopGetConfigurationCount(Query->PeripheralNumber,
					     RegKey, &PeripheralNumber,
					     &MaximumPeripheralNumber));

	/* Loop through Peripherals */
	for (; PeripheralNumber < MaximumPeripheralNumber; PeripheralNumber++) {
	    /* Append the Peripheral Number to the registry key string */
	    UNICODE_STRING PeripheralKey = RegKey;
	    IF_ERR_GOTO(cleanup, Status,
			IopAppendIntegerSubKey(&PeripheralKey,
					       PeripheralNumber));

	    PKEY_VALUE_FULL_INFORMATION PeripheralInformation[3] = { NULL, NULL, NULL };
	    IF_ERR_GOTO(cleanup, Status,
			IopGetConfigurationInformation(PeripheralKey,
						       PeripheralInformation));

            /* We now have everything the caller could possibly want */
	    Status = Query->CalloutRoutine(Query->Context,
					   &PeripheralKey,
					   *Query->BusType,
					   Bus,
					   BusInformation,
					   *Query->ControllerType,
					   ControllerNumber,
					   ControllerInformation,
					   *Query->PeripheralType,
					   PeripheralNumber,
					   PeripheralInformation);

	    /* Cleanup the peripheral information, regardless of the return
	     * status of the callout routine.  */
	    IopFreeConfigurationInformation(PeripheralInformation);

	    /* If callout routine returned error, we should exit the loop */
	    if (!NT_SUCCESS(Status)) {
		goto cleanup;
	    }
	}

    cleanup:
	for (ULONG i = 0; i < ARRAYSIZE(ControllerInformation); i++) {
	    if (ControllerInformation[i] != NULL) {
		ExFreePoolWithTag(ControllerInformation[i], TAG_IO_RESOURCE);
	    }
	}

	/* If something messed up, break from the loop and return.
	 * Otherwise continue the loop and move on to the next controller. */
	if (!NT_SUCCESS(Status)) {
	    return Status;
	}
    }

    return STATUS_SUCCESS;
}

/*
 * Open the key and find out how many subkeys the specified registry key has,
 * as well as the buffer space needed to hold the largest KEY_BASIC_INFORMATION
 * for the subkeys. Note that KEY_BASIC_INFORMATION includes the key name.
 */
static NTSTATUS IopGetSubKeyInfo(IN UNICODE_STRING Key,
				 OUT HANDLE *KeyHandle,
				 OUT ULONG *SubKeyCount,
				 OUT ULONG *SubKeyBufferSize)
{
    assert(KeyHandle != NULL);
    assert(SubKeyCount != NULL);
    assert(SubKeyBufferSize != NULL);

    /* Open a handle to the registry key */
    RET_ERR(IopOpenKey(Key, KeyHandle));
    assert(*KeyHandle != NULL);

    /* Query the key to find out the buffer size we need for KeyFullInformation */
    ULONG LenFullInfo = 0;
    NTSTATUS Status = NtQueryKey(*KeyHandle, KeyFullInformation, NULL, 0,
				 &LenFullInfo);

    if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_TOO_SMALL &&
	Status != STATUS_BUFFER_OVERFLOW) {
	TRACE_(PNPMGR, "NtQueryKey returned error status 0x%x", Status);
	goto out;
    }
    assert(LenFullInfo != 0);

    /* Allocate the buffer */
    PKEY_FULL_INFORMATION FullInfo = ExAllocatePoolWithTag(NonPagedPool, LenFullInfo,
							   TAG_IO_RESOURCE);

    if (!FullInfo) {
	Status = STATUS_NO_MEMORY;
	goto out;
    }

    /* Query the key again to get the full information of the key */
    Status = NtQueryKey(*KeyHandle, KeyFullInformation,
			FullInfo, LenFullInfo, &LenFullInfo);

    if (NT_SUCCESS(Status)) {
	*SubKeyCount = FullInfo->SubKeys;
	*SubKeyBufferSize = FullInfo->MaxNameLen + sizeof(KEY_BASIC_INFORMATION);
    }

    ExFreePoolWithTag(FullInfo, TAG_IO_RESOURCE);
out:
    if (!NT_SUCCESS(Status)) {
	NtClose(*KeyHandle);
    }
    return Status;
}

/*
 * IopQueryBusDescription
 *
 * FUNCTION:
 *      Reads and returns Hardware information from the appropriate hardware
 *      registry key. Helper sub of IoQueryDeviceDescription.
 *
 * ARGUMENTS:
 *      Query         - What the parent function wants.
 *      RootKey	      - Which key to look in
 *      Bus           - Bus Number.
 *
 * RETURNS:
 *      Status
 */
static NTSTATUS IopQueryBusDescription(IN PIO_QUERY Query,
				       IN UNICODE_STRING RootKey,
				       OUT PULONG Bus)
{
    assert(Query != NULL);
    assert(Query->BusType != NULL);

    HANDLE RootKeyHandle = NULL;
    ULONG SubKeyCount = 0;
    ULONG SubKeyBufferSize = 0;
    RET_ERR(IopGetSubKeyInfo(RootKey, &RootKeyHandle, &SubKeyCount, &SubKeyBufferSize));
    assert(RootKeyHandle != NULL);
    if (SubKeyCount == 0) {
	return STATUS_NO_MORE_ENTRIES;
    }
    PKEY_BASIC_INFORMATION BasicInfo = ExAllocatePoolWithTag(NonPagedPool,
							     SubKeyBufferSize,
							     TAG_IO_RESOURCE);
    NTSTATUS Status = STATUS_SUCCESS;
    if (BasicInfo == NULL) {
	Status = STATUS_NO_MEMORY;
	goto out;
    }

    /* Loop through the subkeys to try to find the specified bus */
    for (ULONG BusLoop = 0; BusLoop < SubKeyCount; BusLoop++) {
	ULONG RequiredBufferSize;
	Status = NtEnumerateKey(RootKeyHandle, BusLoop,
				KeyBasicInformation, BasicInfo,
				SubKeyBufferSize, &RequiredBufferSize);

	/* We shouldn't get an error here, but if we did, something
	 * is seriously wrong, but continue anyway. */
	assert(NT_SUCCESS(Status));
	if (!NT_SUCCESS(Status))
	    continue;

	/* Append the bus name to the registry path so we can pass
	 * it onto the recursive call below. */
	UNICODE_STRING BusName = {
	    .Buffer = BasicInfo->Name,
	    .Length = (USHORT)BasicInfo->NameLength,
	    .MaximumLength = (USHORT)BasicInfo->NameLength
	};
	UNICODE_STRING SubKey = RootKey;
	Status = RtlAppendUnicodeToString(&SubKey, L"\\");
	if (!NT_SUCCESS(Status)) {
	    continue;
	}
	Status = RtlAppendUnicodeStringToString(&SubKey, &BusName);
	if (!NT_SUCCESS(Status)) {
	    continue;
	}

	PKEY_VALUE_FULL_INFORMATION BusInfo[] = { NULL, NULL, NULL };
	Status = IopGetConfigurationInformation(SubKey, BusInfo);
	if (!NT_SUCCESS(Status)) {
	    continue;
	}

	/* Check the Configuration Data value for the bus type and bus number */
	if (BusInfo[IoQueryDeviceConfigurationData] != NULL &&
	    BusInfo[IoQueryDeviceConfigurationData]->DataLength != 0 &&
	    (((PCM_FULL_RESOURCE_DESCRIPTOR)((PCHAR)BusInfo[IoQueryDeviceConfigurationData] +
					     BusInfo[IoQueryDeviceConfigurationData]->DataOffset))->InterfaceType
	     == *(Query->BusType))) {
	    /* Found a bus */
	    (*Bus)++;

	    /* Is it the bus we wanted */
	    if (Query->BusNumber == NULL || *(Query->BusNumber) == *Bus) {
		/* If we don't want Controller Information, we're done... call the callback */
		if (Query->ControllerType == NULL) {
		    Status = Query->CalloutRoutine(Query->Context, &SubKey,
						   *Query->BusType, *Bus, BusInfo,
						   0, 0, NULL, 0, 0, NULL);
		} else {
		    /* We want Controller Info...get it */
		    Status = IopQueryDeviceDescription(Query, SubKey, *Bus, BusInfo);
		}
	    }
	}

	IopFreeConfigurationInformation(BusInfo);

	/* Enumerate the buses below us recursively if we haven't found the bus yet */
	if (Query->BusNumber == NULL || *Query->BusNumber != *Bus) {
	    Status = IopQueryBusDescription(Query, SubKey, Bus);
	} else if (Query->BusNumber != NULL || *Query->BusNumber == *Bus) {
	    /* On the other hand, if the caller specified a bus number and we
	     * have found it, we should stop looking and break out of the loop. */
	    break;
	}
    }

    assert(BasicInfo != NULL);
    ExFreePoolWithTag(BasicInfo, TAG_IO_RESOURCE);
out:
    assert(RootKeyHandle != NULL);
    NtClose(RootKeyHandle);

    return Status;
}

/* PUBLIC FUNCTIONS ***********************************************************/

/*
 * @implemented
 */
PCONFIGURATION_INFORMATION IoGetConfigurationInformation()
{
    return (&_SystemConfigurationInformation);
}

/*
 * ROUTINE DESCRIPTION:
 *     Reports hardware resources in the \Registry\Machine\Hardware\ResourceMap
 *     tree, so that a subsequently loaded driver cannot attempt to use the same
 *     resources.
 *
 * ARGUMENTS:
 *     DriverClassName  - The class of driver under which the resource information
 *                        should be stored.
 *     DriverObject     - The driver object that was input to the DriverEntry.
 *     DriverList       - Resources that claimed for the driver rather than per-device.
 *     DriverListSize   - Size in bytes of the DriverList.
 *     DeviceObject     - The device object for which resources should be claimed.
 *     DeviceList       - List of resources which should be claimed for the device.
 *     DeviceListSize   - Size of the per-device resource list in bytes.
 *     OverrideConflict - True if the resources should be cliamed even if a
 *                        conflict is found.
 *     ConflictDetected - Points to a variable that receives TRUE if a conflict
 *                        is detected with another driver.
 *
 * RETURNS:
 *     STATUS_SUCCESS on success. Error status on error.
 *
 * IMPLEMENTATION STATUS:
 *     @unimplemented
 *
 * @remarks This routine must be called at PASSIVE_LEVEL.
 */
NTAPI NTSTATUS IoReportResourceUsage(IN PUNICODE_STRING DriverClassName,
				     IN PDRIVER_OBJECT DriverObject,
				     IN PCM_RESOURCE_LIST DriverList,
				     IN ULONG DriverListSize,
				     IN PDEVICE_OBJECT DeviceObject,
				     IN PCM_RESOURCE_LIST DeviceList,
				     IN ULONG DeviceListSize,
				     IN BOOLEAN OverrideConflict,
				     OUT PBOOLEAN ConflictDetected)
{
    PAGED_CODE();

    DPRINT1("IoReportResourceUsage is half-implemented!\n");

    if (!DriverList && !DeviceList) {
	return STATUS_INVALID_PARAMETER;
    }

//    PCM_RESOURCE_LIST ResourceList = DeviceList ? DeviceList : DriverList;

    NTSTATUS Status = 0;//IopDetectResourceConflict(ResourceList, FALSE, NULL);
	if (Status == STATUS_CONFLICTING_ADDRESSES) {
	    *ConflictDetected = TRUE;

	    if (!OverrideConflict) {
		DPRINT1("Denying an attempt to claim resources currently in use by another device!\n");
		return STATUS_CONFLICTING_ADDRESSES;
	    } else {
		DPRINT1("Proceeding with conflicting resources\n");
	    }
	} else if (!NT_SUCCESS(Status)) {
	    return Status;
	}

    /* TODO: Claim resources in registry */

    *ConflictDetected = FALSE;

    return STATUS_SUCCESS;
}

/*
 * FUNCTION:
 *     Reads and returns Hardware information from the appropriate hardware registry key.
 *
 * ARGUMENTS:
 *     BusType          - Specifies the Bus Type, ie. MCA, ISA, EISA, etc.
 *     BusNumber	- Optionally specifies which of the bus above should be queried.
 *                        If not specified, all buses of the above type will be queried.
 *     ControllerType	- Optionally specifices the controller type. If not specified, only
 *                        the bus information will be queried.
 *     ControllerNumber	- Optionally specifies which of the controllers to query. If not
 *                        specified, all controllers of the specified type will be queried.
 *     PeripheralType -   Optionally specifies the peripheral type. If not specified, only
 *                        the bus information and (optionally) the controller information
 *                        will be queried.
 *     PeripheralNumber - Optionally specifies which of the peripherals to query. If not
 *                        specified, all peripherals of the specified type will be queried.
 *     CalloutRoutine	- Which function to call for each valid query.
 *     Context          - Value to pass to the callback.
 *
 * RETURNS:
 *     Status
 *
 * STATUS:
 *     @implemented
 *
 * @remarks This routine must be called at PASSIVE_LEVEL.
 */
NTAPI NTSTATUS IoQueryDeviceDescription(IN PINTERFACE_TYPE BusType,
					IN OPTIONAL PULONG BusNumber,
					IN OPTIONAL PCONFIGURATION_TYPE ControllerType,
					IN OPTIONAL PULONG ControllerNumber,
					IN OPTIONAL PCONFIGURATION_TYPE PeripheralType,
					IN OPTIONAL PULONG PeripheralNumber,
					IN PIO_QUERY_DEVICE_ROUTINE CalloutRoutine,
					IN OUT OPTIONAL PVOID Context)
{
    PAGED_CODE();

    if (BusType == NULL) {
	return STATUS_INVALID_PARAMETER;
    }

    /* Set up the string for the root registry key. Note that this string
     * buffer is reused during the registry queries below. We simply
     * modify the string Length to append and truncate the string. */
    UNICODE_STRING RootKey = {
	.Length = 0,
	.MaximumLength = 2048,
	.Buffer = NULL
    };
    HANDLE RootKeyHandle = NULL;

    RootKey.Buffer = ExAllocatePoolWithTag(NonPagedPool, RootKey.MaximumLength,
					   TAG_IO_RESOURCE);
    if (RootKey.Buffer == NULL) {
	return STATUS_NO_MEMORY;
    }

    NTSTATUS Status;
    PKEY_BASIC_INFORMATION BasicInfo = NULL;
    IF_ERR_GOTO(out, Status, RtlAppendUnicodeToString(&RootKey,
						      DEVICE_DESCRIPTION_KEY));

    /* Open a handle to the root registry key and find out how many subkeys
     * the root key has, as well as the buffer space we need. */
    ULONG SubKeyCount = 0;
    ULONG SubKeyBufferSize = 0;
    IF_ERR_GOTO(out, Status,
		IopGetSubKeyInfo(RootKey, &RootKeyHandle,
				 &SubKeyCount, &SubKeyBufferSize));
    BasicInfo = ExAllocatePoolWithTag(NonPagedPool, SubKeyBufferSize,
				      TAG_IO_RESOURCE);
    if (BasicInfo == NULL) {
	Status = STATUS_NO_MEMORY;
	goto out;
    }

    /* Enumerate each subkey to find the specified bus type and bus number */
    for (ULONG BusLoop = 0; BusLoop < SubKeyCount; BusLoop++) {
	/* Enumerate the Key */
	ULONG RequiredBufferSize;
	Status = NtEnumerateKey(RootKeyHandle, BusLoop, KeyBasicInformation,
				BasicInfo, SubKeyBufferSize, &RequiredBufferSize);

	/* We shouldn't get an error here, but if we did, something
	 * is seriously wrong, but continue anyway. */
	assert(NT_SUCCESS(Status));
	if (!NT_SUCCESS(Status))
	    continue;

	/* We are only interested the following three adapter types so skip anything
	 * that isn't on the list. */
	PCWSTR AdapterNames[] = {
	    L"MultifunctionAdapter",
	    L"EisaAdapter",
	    L"TcAdapter"
	};
	BOOLEAN Skip = TRUE;
	UNICODE_STRING BusName = {
	    .Buffer = BasicInfo->Name,
	    .Length = (USHORT)BasicInfo->NameLength,
	    .MaximumLength = (USHORT)BasicInfo->NameLength
	};
	TRACE_(PNPMGR, "Got adapter name %wZ\n", &BusName);
	for (ULONG i = 0; i < ARRAYSIZE(AdapterNames); i++) {
	    Skip &= !!wcsncmp(BasicInfo->Name, AdapterNames[i],
			      BasicInfo->NameLength / sizeof(WCHAR));
	}
	if (Skip) {
	    continue;
	}

	/* Append the bus name to to the registry path so we can pass
	 * it onto the helper function below. */
	UNICODE_STRING SubKey = RootKey;
	Status = RtlAppendUnicodeToString(&SubKey, L"\\");
	if (!NT_SUCCESS(Status)) {
	    continue;
	}
	Status = RtlAppendUnicodeStringToString(&SubKey, &BusName);
	if (!NT_SUCCESS(Status)) {
	    continue;
	}

	/* Call the helper function to enumerate the buses below us recursively
	 * until we find the bus number specified by the caller. This will also
	 * invoke the specified callback routine appropriately. */
	IO_QUERY Query = {
	    .BusType = BusType,
	    .BusNumber = BusNumber,
	    .ControllerType = ControllerType,
	    .ControllerNumber = ControllerNumber,
	    .PeripheralType = PeripheralType,
	    .PeripheralNumber = PeripheralNumber,
	    .CalloutRoutine = CalloutRoutine,
	    .Context = Context
	};
	ULONG Bus = -1;		/* Indicates root bus */
	Status = IopQueryBusDescription(&Query, SubKey, &Bus);

	/* Caller specified a bus number and we have found it. Return success. */
	if (BusNumber != NULL && *BusNumber == Bus) {
	    break;
	}
    }

out:
    if (BasicInfo != NULL) {
	ExFreePoolWithTag(BasicInfo, TAG_IO_RESOURCE);
    }
    if (RootKeyHandle != NULL) {
	NtClose(RootKeyHandle);
    }
    ExFreePoolWithTag(RootKey.Buffer, TAG_IO_RESOURCE);

    return Status;
}

/*
 * @implemented
 *
 * FUNCTION:
 *      Reports hardware resources of the Hardware Abstraction Layer (HAL) in the
 *      \Registry\Machine\Hardware\ResourceMap tree.
 *
 * ARGUMENTS:
 *      HalDescription - Descriptive name of the HAL.
 *      RawList        - List of raw (bus specific) resources which should be
 *                       claimed for the HAL.
 *      TranslatedList - List of translated (system wide) resources which should
 *                       be claimed for the HAL.
 *      ListSize       - Size in bytes of the raw and translated resource lists.
 *                       Both lists have the same size.
 *
 * RETURNS:
 *      Status.
 *
 * @remarks This routine must be called at PASSIVE_LEVEL.
 */
NTAPI NTSTATUS IoReportHalResourceUsage(IN PUNICODE_STRING HalDescription,
					IN PCM_RESOURCE_LIST RawList,
					IN PCM_RESOURCE_LIST TranslatedList,
					IN ULONG ListSize)
{
    PAGED_CODE();
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING Name;
    ULONG Disposition;
    NTSTATUS Status;
    HANDLE ResourcemapKey;
    HANDLE HalKey;
    HANDLE DescriptionKey;

    /* Open/Create 'RESOURCEMAP' key. */
    RtlInitUnicodeString(&Name,
			 L"\\Registry\\Machine\\HARDWARE\\RESOURCEMAP");
    InitializeObjectAttributes(&ObjectAttributes,
			       &Name,
			       OBJ_CASE_INSENSITIVE | OBJ_OPENIF, 0, NULL);
    Status = NtCreateKey(&ResourcemapKey,
			 KEY_ALL_ACCESS,
			 &ObjectAttributes,
			 0, NULL, REG_OPTION_VOLATILE, &Disposition);
    if (!NT_SUCCESS(Status))
	return (Status);

    /* Open/Create 'Hardware Abstraction Layer' key */
    RtlInitUnicodeString(&Name, L"Hardware Abstraction Layer");
    InitializeObjectAttributes(&ObjectAttributes,
			       &Name,
			       OBJ_CASE_INSENSITIVE | OBJ_OPENIF,
			       ResourcemapKey, NULL);
    Status = NtCreateKey(&HalKey,
			 KEY_ALL_ACCESS,
			 &ObjectAttributes,
			 0, NULL, REG_OPTION_VOLATILE, &Disposition);
    NtClose(ResourcemapKey);
    if (!NT_SUCCESS(Status))
	return (Status);

    /* Create 'HalDescription' key */
    InitializeObjectAttributes(&ObjectAttributes,
			       HalDescription,
			       OBJ_CASE_INSENSITIVE, HalKey, NULL);
    Status = NtCreateKey(&DescriptionKey,
			 KEY_ALL_ACCESS,
			 &ObjectAttributes,
			 0, NULL, REG_OPTION_VOLATILE, &Disposition);
    NtClose(HalKey);
    if (!NT_SUCCESS(Status))
	return (Status);

    /* Add '.Raw' value. */
    RtlInitUnicodeString(&Name, L".Raw");
    Status = NtSetValueKey(DescriptionKey,
			   &Name, 0, REG_RESOURCE_LIST, RawList, ListSize);
    if (!NT_SUCCESS(Status)) {
	NtClose(DescriptionKey);
	return (Status);
    }

    /* Add '.Translated' value. */
    RtlInitUnicodeString(&Name, L".Translated");
    Status = NtSetValueKey(DescriptionKey,
			   &Name,
			   0, REG_RESOURCE_LIST, TranslatedList, ListSize);
    NtClose(DescriptionKey);

    return (Status);
}

/*
 * @implemented
 */
NTAPI NTSTATUS IoSetSystemPartition(IN PUNICODE_STRING VolumeNameString)
{
    NTSTATUS Status;
    HANDLE RootHandle, KeyHandle;
    UNICODE_STRING HKLMSystem, KeyString;
    WCHAR Buffer[sizeof(L"SystemPartition") / sizeof(WCHAR)];

    RtlInitUnicodeString(&HKLMSystem, L"\\REGISTRY\\MACHINE\\SYSTEM");

    /* Open registry to save data (HKLM\SYSTEM) */
    Status = IopOpenKeyEx(&RootHandle, NULL, &HKLMSystem, KEY_ALL_ACCESS);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    /* Create or open Setup subkey */
    KeyString.Buffer = Buffer;
    KeyString.Length = sizeof(L"Setup") - sizeof(UNICODE_NULL);
    KeyString.MaximumLength = sizeof(L"Setup");
    RtlCopyMemory(Buffer, L"Setup", sizeof(L"Setup"));
    Status = IopCreateRegistryKeyEx(&KeyHandle, RootHandle, &KeyString, KEY_ALL_ACCESS,
				    REG_OPTION_NON_VOLATILE, NULL);
    NtClose(RootHandle);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    /* Store caller value */
    KeyString.Length = sizeof(L"SystemPartition") - sizeof(UNICODE_NULL);
    KeyString.MaximumLength = sizeof(L"SystemPartition");
    RtlCopyMemory(Buffer, L"SystemPartition", sizeof(L"SystemPartition"));
    Status = NtSetValueKey(KeyHandle, &KeyString, 0, REG_SZ, VolumeNameString->Buffer,
			   VolumeNameString->Length + sizeof(UNICODE_NULL));
    NtClose(KeyHandle);

    return Status;
}
