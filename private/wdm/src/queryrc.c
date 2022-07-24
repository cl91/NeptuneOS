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

static NTSTATUS IopAppendArcTypeSubKey(IN PUNICODE_STRING String,
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
static NTSTATUS IopGetSubKeyCount(IN PUNICODE_STRING Key,
				  OUT ULONG *SubKeyCount)
{
    assert(Key != NULL);
    assert(SubKeyCount != NULL);

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, Key,
			       OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE KeyHandle = NULL;
    PKEY_FULL_INFORMATION FullInfo = NULL;
    NTSTATUS Status = NtOpenKey(&KeyHandle, KEY_READ, &ObjectAttributes);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }

    /* Find out how much buffer space we should allocate */
    ULONG LenFullInfo = 0;
    Status = NtQueryKey(KeyHandle, KeyFullInformation, NULL, 0, &LenFullInfo);
    if (!NT_SUCCESS(Status) || LenFullInfo == 0) {
	goto out;
    }

    /* Allocate the key information buffer */
    FullInfo = ExAllocatePoolWithTag(LenFullInfo, TAG_IO_RESOURCE);
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
    if (KeyHandle != NULL) {
	NtClose(KeyHandle);
    }
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
					 IN PUNICODE_STRING ConfigKey,
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

/*
 * Read the configuration data for the given controller/peripheral.
 *
 * The Information array must have exactly three elements and must be zero initialized.
 */
static NTSTATUS IopGetConfigurationData(IN PUNICODE_STRING RegKey,
					OUT PKEY_VALUE_FULL_INFORMATION *Information)
{
    assert(RegKey != NULL);
    assert(Information != NULL);
    assert(Information[0] == NULL);
    assert(Information[1] == NULL);
    assert(Information[2] == NULL);

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, RegKey,
			       OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE KeyHandle = NULL;
    NTSTATUS Status = NtOpenKey(&KeyHandle, KEY_READ, &ObjectAttributes);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }

    PWSTR SubkeyNames[] = {
	L"Identifier",
	L"Configuration Data",
	L"Component Information"
    };

    /* Read the configuration data from registry */
    for (ULONG i = 0; i < ARRAYSIZE(SubkeyNames); i++) {
	UNICODE_STRING SubkeyString;
	RtlInitUnicodeString(&SubkeyString, SubkeyNames[i]);

	/* Find out how much buffer space we need */
	ULONG BufferSize = 0;
	Status = NtQueryValueKey(KeyHandle, &SubkeyString,
				 KeyValueFullInformation, NULL, 0,
				 &BufferSize);
	if (!NT_SUCCESS(Status)) {
	    goto cleanup;
	}
	assert(BufferSize != 0);

	/* Allocate the required buffer space */
	Information[i] = ExAllocatePoolWithTag(BufferSize,
					       TAG_IO_RESOURCE);
	if (Information[i] == NULL) {
	    Status = STATUS_NO_MEMORY;
	    goto cleanup;
	}

	/* Get the configuration information */
	Status = NtQueryValueKey(KeyHandle, &SubkeyString,
				 KeyValueFullInformation,
				 Information[i],
				 BufferSize,
				 &BufferSize);
	/* We should never get these errors because we asked for the
	 * correct buffer size before. */
	assert(Status != STATUS_BUFFER_TOO_SMALL);
	assert(Status != STATUS_BUFFER_OVERFLOW);
	if (!NT_SUCCESS(Status)) {
	    goto cleanup;
	}
    }

    /* If we got here, everything went well */
    Status = STATUS_SUCCESS;
    goto out;

cleanup:
    for (ULONG i = 0; i < ARRAYSIZE(SubkeyNames); i++) {
	if (Information[i] != NULL) {
	    ExFreePoolWithTag(Information[i], TAG_IO_RESOURCE);
	}
    }

out:
    if (KeyHandle != NULL) {
	NtClose(KeyHandle);
    }
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
 *     RootKeyHandle  - Handle to the key
 *     Bus            - Bus Number.
 *     BusInformation - The Configuration Information Sent
 *
 * RETURNS:
 *     Status
 */
static NTSTATUS IopQueryDeviceDescription(IN PIO_QUERY Query,
					  IN UNICODE_STRING RootKey,
					  IN HANDLE RootKeyHandle,
					  IN ULONG Bus,
					  OUT PKEY_VALUE_FULL_INFORMATION *BusInformation)
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
				     &ControllerRootKey,
				     &ControllerNumber,
				     &MaximumControllerNumber));

    /* Loop through controllers */
    for (; ControllerNumber < MaximumControllerNumber; ControllerNumber++) {
	/* Append the controller number subkey to the root controller key */
	UNICODE_STRING RegKey = ControllerRootKey;
	RET_ERR(IopAppendIntegerSubKey(&RegKey, ControllerNumber));

	PKEY_VALUE_FULL_INFORMATION ControllerInformation[] = { NULL, NULL, NULL };
	RET_ERR(IopGetConfigurationData(&RegKey, ControllerInformation));

	/* We now have Bus *AND* Controller Information. Is it enough? */
	NTSTATUS Status = STATUS_SUCCESS;
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

	/* Not enough...caller also wants peripheral name */
	IF_ERR_GOTO(cleanup, Status,
		    IopAppendArcTypeSubKey(&RegKey, *Query->PeripheralType));

	ULONG PeripheralNumber;
	ULONG MaximumPeripheralNumber;
	IF_ERR_GOTO(cleanup, Status,
		    IopGetConfigurationCount(Query->PeripheralNumber,
					     &RegKey, &PeripheralNumber,
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
			IopGetConfigurationData(&PeripheralKey,
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

	    /* Cleanup the peripheral information */
	    for (ULONG i = 0; i < ARRAYSIZE(PeripheralInformation); i++) {
		if (PeripheralInformation[i] != NULL) {
		    ExFreePoolWithTag(PeripheralInformation[i], TAG_IO_RESOURCE);
		}
	    }

	    /* If callout routine returned error, we should clean up and return */
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
 * IopQueryBusDescription
 *
 * FUNCTION:
 *      Reads and returns Hardware information from the appropriate hardware
 *      registry key. Helper sub of IoQueryDeviceDescription. Has two modes
 *      of operation, either looking for Root Bus Types or for sub-Bus
 *      information.
 *
 * ARGUMENTS:
 *      Query         - What the parent function wants.
 *      RootKey	      - Which key to look in
 *      RootKeyHandle - Handle to the key
 *      Bus           - Bus Number.
 *      KeyIsRoot     - Whether we are looking for Root Bus Types or
 *                      information under them.
 *
 * RETURNS:
 *      Status
 */
static NTSTATUS IopQueryBusDescription(IN PIO_QUERY Query,
				       IN UNICODE_STRING RootKey,
				       IN HANDLE RootKeyHandle,
				       OUT PULONG Bus,
				       IN BOOLEAN KeyIsRoot)
{
    NTSTATUS Status;
    ULONG BusLoop;
    UNICODE_STRING SubRootRegName;
    UNICODE_STRING BusString;
    UNICODE_STRING SubBusString;
    ULONG LenBasicInformation = 0;
    ULONG LenFullInformation;
    ULONG LenKeyFullInformation;
    ULONG LenKey;
    HANDLE SubRootKeyHandle;
    PKEY_FULL_INFORMATION FullInformation;
    PKEY_BASIC_INFORMATION BasicInformation = NULL;
    OBJECT_ATTRIBUTES ObjectAttributes;
    PKEY_VALUE_FULL_INFORMATION BusInformation[3] = { NULL, NULL, NULL };

    /* How much buffer space */
    Status =
	NtQueryKey(RootKeyHandle, KeyFullInformation, NULL, 0,
		   &LenFullInformation);

    if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_TOO_SMALL
	&& Status != STATUS_BUFFER_OVERFLOW)
	return Status;

    /* Allocate it */
    FullInformation =
	ExAllocatePoolWithTag(LenFullInformation,
			      TAG_IO_RESOURCE);

    if (!FullInformation)
	return STATUS_NO_MEMORY;

    /* Get the Information */
    Status =
	NtQueryKey(RootKeyHandle, KeyFullInformation, FullInformation,
		   LenFullInformation, &LenFullInformation);

    /* Everything was fine */
    if (NT_SUCCESS(Status)) {
	/* Buffer needed for all the keys under this one */
	LenBasicInformation =
	    FullInformation->MaxNameLen + sizeof(KEY_BASIC_INFORMATION);

	/* Allocate it */
	BasicInformation =
	    ExAllocatePoolWithTag(LenBasicInformation,
				  TAG_IO_RESOURCE);
    }

    /* Deallocate the old Buffer */
    ExFreePoolWithTag(FullInformation, TAG_IO_RESOURCE);

    /* Try to find a Bus */
    for (BusLoop = 0; NT_SUCCESS(Status); BusLoop++) {
	/* Bus parameter was passed and number was matched */
	if ((Query->BusNumber) && (*(Query->BusNumber)) == *Bus)
	    break;

	/* Enumerate the Key */
	Status = NtEnumerateKey(RootKeyHandle,
				BusLoop,
				KeyBasicInformation,
				BasicInformation,
				LenBasicInformation, &LenKey);

	/* Everything enumerated */
	if (!NT_SUCCESS(Status))
	    break;

	/* What Bus are we going to go down? (only check if this is a Root Key) */
	if (KeyIsRoot) {
	    if (wcsncmp
		(BasicInformation->Name, L"MultifunctionAdapter",
		 BasicInformation->NameLength / 2)
		&& wcsncmp(BasicInformation->Name, L"EisaAdapter",
			   BasicInformation->NameLength / 2)
		&& wcsncmp(BasicInformation->Name, L"TcAdapter",
			   BasicInformation->NameLength / 2)) {
		/* Nothing found, check next */
		continue;
	    }
	}

	/* Enumerate the Bus. */
	BusString.Buffer = BasicInformation->Name;
	BusString.Length = (USHORT) BasicInformation->NameLength;
	BusString.MaximumLength = (USHORT) BasicInformation->NameLength;

	/* Open a handle to the Root Registry Key */
	InitializeObjectAttributes(&ObjectAttributes,
				   &BusString,
				   OBJ_CASE_INSENSITIVE,
				   RootKeyHandle, NULL);

	Status = NtOpenKey(&SubRootKeyHandle, KEY_READ, &ObjectAttributes);

	/* Go on if we can't */
	if (!NT_SUCCESS(Status))
	    continue;

	/* Key opened. Create the path */
	SubRootRegName = RootKey;
	RtlAppendUnicodeToString(&SubRootRegName, L"\\");
	RtlAppendUnicodeStringToString(&SubRootRegName, &BusString);

	if (!KeyIsRoot) {
	    /* Parsing a SubBus-key */
	    int SubBusLoop;
	    PWSTR Strings[3] = {
		L"Identifier",
		L"Configuration Data",
		L"Component Information"
	    };

	    for (SubBusLoop = 0; SubBusLoop < 3; SubBusLoop++) {
		/* Identifier String First */
		RtlInitUnicodeString(&SubBusString, Strings[SubBusLoop]);

		/* How much buffer space */
		NtQueryValueKey(SubRootKeyHandle, &SubBusString,
				KeyValueFullInformation, NULL, 0,
				&LenKeyFullInformation);

		/* Allocate it */
		BusInformation[SubBusLoop] =
		    ExAllocatePoolWithTag(LenKeyFullInformation,
					  TAG_IO_RESOURCE);

		/* Get the Information */
		Status =
		    NtQueryValueKey(SubRootKeyHandle, &SubBusString,
				    KeyValueFullInformation,
				    BusInformation[SubBusLoop],
				    LenKeyFullInformation,
				    &LenKeyFullInformation);
	    }

	    if (NT_SUCCESS(Status)) {
		/* Do we have something */
		if (BusInformation[1] != NULL &&
		    BusInformation[1]->DataLength != 0 &&
		    /* Does it match what we want? */
		    (((PCM_FULL_RESOURCE_DESCRIPTOR)
		      ((ULONG_PTR) BusInformation[1] +
		       BusInformation[1]->DataOffset))->InterfaceType ==
		     *(Query->BusType))) {
		    /* Found a bus */
		    (*Bus)++;

		    /* Is it the bus we wanted */
		    if (Query->BusNumber == NULL
			|| *(Query->BusNumber) == *Bus) {
			/* If we don't want Controller Information, we're done... call the callback */
			if (Query->ControllerType == NULL) {
			    Status = Query->CalloutRoutine(Query->Context,
							   &SubRootRegName,
							   *(Query->
							     BusType),
							   *Bus,
							   BusInformation,
							   0, 0, NULL, 0,
							   0, NULL);
			} else {
			    /* We want Controller Info...get it */
			    Status =
				IopQueryDeviceDescription(Query,
							  SubRootRegName,
							  RootKeyHandle,
							  *Bus,
							  (PKEY_VALUE_FULL_INFORMATION
							   *)
							  BusInformation);
			}
		    }
		}
	    }

	    /* Free the allocated memory */
	    for (SubBusLoop = 0; SubBusLoop < 3; SubBusLoop++) {
		if (BusInformation[SubBusLoop]) {
		    ExFreePoolWithTag(BusInformation[SubBusLoop],
				      TAG_IO_RESOURCE);
		    BusInformation[SubBusLoop] = NULL;
		}
	    }

	    /* Exit the Loop if we found the bus */
	    if (Query->BusNumber != NULL && *(Query->BusNumber) == *Bus) {
		NtClose(SubRootKeyHandle);
		SubRootKeyHandle = NULL;
		continue;
	    }
	}

	/* Enumerate the buses below us recursively if we haven't found the bus yet */
	Status =
	    IopQueryBusDescription(Query, SubRootRegName, SubRootKeyHandle,
				   Bus, !KeyIsRoot);

	/* Everything enumerated */
	if (Status == STATUS_NO_MORE_ENTRIES)
	    Status = STATUS_SUCCESS;

	NtClose(SubRootKeyHandle);
	SubRootKeyHandle = NULL;
    }

    /* Free the last remaining Allocated Memory */
    if (BasicInformation)
	ExFreePoolWithTag(BasicInformation, TAG_IO_RESOURCE);

    return Status;
}

static NTSTATUS IopFetchConfigurationInformation(OUT PWSTR * SymbolicLinkList,
						 IN GUID Guid,
						 IN ULONG ExpectedInterfaces,
						 IN PULONG Interfaces)
{
    NTSTATUS Status;
    ULONG IntInterfaces = 0;
    PWSTR IntSymbolicLinkList;

    /* Get the associated enabled interfaces with the given GUID */
    Status = IoGetDeviceInterfaces(&Guid, NULL, 0, SymbolicLinkList);
    if (!NT_SUCCESS(Status)) {
	/* Zero output and leave */
	if (SymbolicLinkList != 0) {
	    *SymbolicLinkList = 0;
	}

	return STATUS_UNSUCCESSFUL;
    }

    IntSymbolicLinkList = *SymbolicLinkList;

    /* Count the number of enabled interfaces by counting the number of symbolic links */
    while (*IntSymbolicLinkList != UNICODE_NULL) {
	IntInterfaces++;
	IntSymbolicLinkList +=
	    wcslen(IntSymbolicLinkList) +
	    (sizeof(UNICODE_NULL) / sizeof(WCHAR));
    }

    /* Matching result will define the result */
    Status =
	(IntInterfaces >=
	 ExpectedInterfaces) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    /* Finally, give back to the caller the number of found interfaces */
    *Interfaces = IntInterfaces;

    return Status;
}

static VOID IopStoreSystemPartitionInformation(IN PUNICODE_STRING NtSystemPartitionDeviceName,
					       IN PUNICODE_STRING OsLoaderPathName)
{
    NTSTATUS Status;
    UNICODE_STRING LinkTarget, KeyName;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE LinkHandle, RegistryHandle, KeyHandle;
    WCHAR LinkTargetBuffer[256];
    UNICODE_STRING CmRegistryMachineSystemName =
	RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SYSTEM");

    ASSERT(NtSystemPartitionDeviceName->MaximumLength >=
	   NtSystemPartitionDeviceName->Length + sizeof(WCHAR));
    ASSERT(NtSystemPartitionDeviceName->
	   Buffer[NtSystemPartitionDeviceName->Length / sizeof(WCHAR)] ==
	   UNICODE_NULL);
    ASSERT(OsLoaderPathName->MaximumLength >=
	   OsLoaderPathName->Length + sizeof(WCHAR));
    ASSERT(OsLoaderPathName->
	   Buffer[OsLoaderPathName->Length / sizeof(WCHAR)] ==
	   UNICODE_NULL);

    /* First define needed stuff to open NtSystemPartitionDeviceName symbolic link */
    InitializeObjectAttributes(&ObjectAttributes,
			       NtSystemPartitionDeviceName,
			       OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			       NULL, NULL);

    /* Open NtSystemPartitionDeviceName symbolic link */
    Status = NtOpenSymbolicLinkObject(&LinkHandle,
				      SYMBOLIC_LINK_QUERY,
				      &ObjectAttributes);
    if (!NT_SUCCESS(Status)) {
	DPRINT("Failed to open symlink %wZ, Status=%x\n",
	       NtSystemPartitionDeviceName, Status);
	return;
    }

    /* Prepare the string that will receive where symbolic link points to */
    LinkTarget.Length = 0;
    /* We will zero the end of the string after having received it */
    LinkTarget.MaximumLength =
	sizeof(LinkTargetBuffer) - sizeof(UNICODE_NULL);
    LinkTarget.Buffer = LinkTargetBuffer;

    /* Query target */
    Status = NtQuerySymbolicLinkObject(LinkHandle, &LinkTarget, NULL);

    /* We are done with symbolic link */
    NtClose(LinkHandle);

    if (!NT_SUCCESS(Status)) {
	DPRINT("Failed querying symlink %wZ, Status=%x\n",
	       NtSystemPartitionDeviceName, Status);
	return;
    }

    /* As promised, we zero the end */
    LinkTarget.Buffer[LinkTarget.Length / sizeof(WCHAR)] = UNICODE_NULL;

    /* Open registry to save data (HKLM\SYSTEM) */
    Status = IopOpenRegistryKeyEx(&RegistryHandle,
				  NULL,
				  &CmRegistryMachineSystemName,
				  KEY_ALL_ACCESS);
    if (!NT_SUCCESS(Status)) {
	DPRINT("Failed to open HKLM\\SYSTEM, Status=%x\n", Status);
	return;
    }

    /* Open or create the Setup subkey where we'll store in */
    RtlInitUnicodeString(&KeyName, L"Setup");

    Status = IopCreateRegistryKeyEx(&KeyHandle,
				    RegistryHandle,
				    &KeyName,
				    KEY_ALL_ACCESS,
				    REG_OPTION_NON_VOLATILE, NULL);

    /* We're done with HKLM\SYSTEM */
    NtClose(RegistryHandle);

    if (!NT_SUCCESS(Status)) {
	DPRINT("Failed opening/creating Setup key, Status=%x\n", Status);
	return;
    }

    /* Prepare first data writing... */
    RtlInitUnicodeString(&KeyName, L"SystemPartition");

    /* Write SystemPartition value which is the target of the symbolic link */
    Status = NtSetValueKey(KeyHandle,
			   &KeyName,
			   0,
			   REG_SZ,
			   LinkTarget.Buffer,
			   LinkTarget.Length + sizeof(WCHAR));
    if (!NT_SUCCESS(Status)) {
	DPRINT("Failed writing SystemPartition value, Status=%x\n",
	       Status);
    }

    /* Prepare for second data writing... */
    RtlInitUnicodeString(&KeyName, L"OsLoaderPath");

    /* Remove trailing slash if any (one slash only excepted) */
    if (OsLoaderPathName->Length > sizeof(WCHAR) &&
	OsLoaderPathName->
	Buffer[(OsLoaderPathName->Length / sizeof(WCHAR)) - 1] ==
	OBJ_NAME_PATH_SEPARATOR) {
	OsLoaderPathName->Length -= sizeof(WCHAR);
	OsLoaderPathName->Buffer[OsLoaderPathName->Length /
				 sizeof(WCHAR)] = UNICODE_NULL;
    }

    /* Then, write down data */
    Status = NtSetValueKey(KeyHandle,
			   &KeyName,
			   0,
			   REG_SZ,
			   OsLoaderPathName->Buffer,
			   OsLoaderPathName->Length +
			   sizeof(UNICODE_NULL));
    if (!NT_SUCCESS(Status)) {
	DPRINT("Failed writing OsLoaderPath value, Status=%x\n", Status);
    }

    /* We're finally done! */
    NtClose(KeyHandle);
}

/* PUBLIC FUNCTIONS ***********************************************************/

/*
 * @implemented
 */
NTAPI PCONFIGURATION_INFORMATION IoGetConfigurationInformation()
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
    DPRINT1("IoReportResourceUsage is half-implemented!\n");

    if (!DriverList && !DeviceList) {
	return STATUS_INVALID_PARAMETER;
    }

    PCM_RESOURCE_LIST ResourceList = DeviceList ? DeviceList : DriverList;

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
 *     BusType          - MCA, ISA, EISA...specifies the Bus Type
 *     BusNumber	- Which bus of above should be queried
 *     ControllerType	- Specifices the Controller Type
 *     ControllerNumber	- Which of the controllers to query.
 *     CalloutRoutine	- Which function to call for each valid query.
 *     Context          - Value to pass to the callback.
 *
 * RETURNS:
 *     Status
 *
 * STATUS:
 *     @implemented
 */
NTAPI NTSTATUS IoQueryDeviceDescription(IN OPTIONAL PINTERFACE_TYPE BusType,
					IN OPTIONAL PULONG BusNumber,
					IN OPTIONAL PCONFIGURATION_TYPE ControllerType,
					IN OPTIONAL PULONG ControllerNumber,
					IN OPTIONAL PCONFIGURATION_TYPE PeripheralType,
					IN OPTIONAL PULONG PeripheralNumber,
					IN PIO_QUERY_DEVICE_ROUTINE CalloutRoutine,
					IN OUT OPTIONAL PVOID Context)
{
    NTSTATUS Status;
    ULONG BusLoopNumber = -1;	/* Root Bus */
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING RootRegKey;
    HANDLE RootRegHandle;
    IO_QUERY Query;

    /* Set up the String */
    RootRegKey.Length = 0;
    RootRegKey.MaximumLength = 2048;
    RootRegKey.Buffer =
	ExAllocatePoolWithTag(RootRegKey.MaximumLength,
			      TAG_IO_RESOURCE);
    RtlAppendUnicodeToString(&RootRegKey,
			     L"\\REGISTRY\\MACHINE\\HARDWARE\\DESCRIPTION\\SYSTEM");

    /* Open a handle to the Root Registry Key */
    InitializeObjectAttributes(&ObjectAttributes,
			       &RootRegKey,
			       OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = NtOpenKey(&RootRegHandle, KEY_READ, &ObjectAttributes);

    if (NT_SUCCESS(Status)) {
	/* Use a helper function to loop though this key and get the info */
	Query.BusType = BusType;
	Query.BusNumber = BusNumber;
	Query.ControllerType = ControllerType;
	Query.ControllerNumber = ControllerNumber;
	Query.PeripheralType = PeripheralType;
	Query.PeripheralNumber = PeripheralNumber;
	Query.CalloutRoutine = CalloutRoutine;
	Query.Context = Context;
	Status =
	    IopQueryBusDescription(&Query, RootRegKey, RootRegHandle,
				   &BusLoopNumber, TRUE);

	/* Close registry */
	NtClose(RootRegHandle);
    }

    /* Free Memory */
    ExFreePoolWithTag(RootRegKey.Buffer, TAG_IO_RESOURCE);

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
 */
NTAPI NTSTATUS IoReportHalResourceUsage(IN PUNICODE_STRING HalDescription,
					IN PCM_RESOURCE_LIST RawList,
					IN PCM_RESOURCE_LIST TranslatedList,
					IN ULONG ListSize)
{
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
