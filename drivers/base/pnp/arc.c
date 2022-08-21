//
// ARC Component Configuration Routines
//

#include "arc.h"

/* This is the same as the ArcTypes private/wdm/src/queryrc.c. We
 * should probably export the ArcTypes in wdm.dll and use that one.
 * On the other hand, this is strictly for legacy devices so it's
 * probably not worth it. */
UNICODE_STRING CmTypeName[MaximumType + 1] = {
    RTL_CONSTANT_STRING(L"System"),
    RTL_CONSTANT_STRING(L"CentralProcessor"),
    RTL_CONSTANT_STRING(L"FloatingPointProcessor"),
    RTL_CONSTANT_STRING(L"PrimaryICache"),
    RTL_CONSTANT_STRING(L"PrimaryDCache"),
    RTL_CONSTANT_STRING(L"SecondaryICache"),
    RTL_CONSTANT_STRING(L"SecondaryDCache"),
    RTL_CONSTANT_STRING(L"SecondaryCache"),
    RTL_CONSTANT_STRING(L"EisaAdapter"),
    RTL_CONSTANT_STRING(L"TcAdapter"),
    RTL_CONSTANT_STRING(L"ScsiAdapter"),
    RTL_CONSTANT_STRING(L"DtiAdapter"),
    RTL_CONSTANT_STRING(L"MultifunctionAdapter"),
    RTL_CONSTANT_STRING(L"DiskController"),
    RTL_CONSTANT_STRING(L"TapeController"),
    RTL_CONSTANT_STRING(L"CdRomController"),
    RTL_CONSTANT_STRING(L"WormController"),
    RTL_CONSTANT_STRING(L"SerialController"),
    RTL_CONSTANT_STRING(L"NetworkController"),
    RTL_CONSTANT_STRING(L"DisplayController"),
    RTL_CONSTANT_STRING(L"ParallelController"),
    RTL_CONSTANT_STRING(L"PointerController"),
    RTL_CONSTANT_STRING(L"KeyboardController"),
    RTL_CONSTANT_STRING(L"AudioController"),
    RTL_CONSTANT_STRING(L"OtherController"),
    RTL_CONSTANT_STRING(L"DiskPeripheral"),
    RTL_CONSTANT_STRING(L"FloppyDiskPeripheral"),
    RTL_CONSTANT_STRING(L"TapePeripheral"),
    RTL_CONSTANT_STRING(L"ModemPeripheral"),
    RTL_CONSTANT_STRING(L"MonitorPeripheral"),
    RTL_CONSTANT_STRING(L"PrinterPeripheral"),
    RTL_CONSTANT_STRING(L"PointerPeripheral"),
    RTL_CONSTANT_STRING(L"KeyboardPeripheral"),
    RTL_CONSTANT_STRING(L"TerminalPeripheral"),
    RTL_CONSTANT_STRING(L"OtherPeripheral"),
    RTL_CONSTANT_STRING(L"LinePeripheral"),
    RTL_CONSTANT_STRING(L"NetworkPeripheral"),
    RTL_CONSTANT_STRING(L"SystemMemory"),
    RTL_CONSTANT_STRING(L"DockingInformation"),
    RTL_CONSTANT_STRING(L"RealModeIrqRoutingTable"),
    RTL_CONSTANT_STRING(L"RealModePCIEnumeration"),
    RTL_CONSTANT_STRING(L"Undefined")
};

//
// MultiFunction Adapter Recognizer Structure
//
typedef struct _CMP_MF_TYPE {
    PCHAR Identifier;
    USHORT InterfaceType;
    USHORT Count;
} CMP_MF_TYPE, *PCMP_MF_TYPE;

CMP_MF_TYPE CmpMultifunctionTypes[] = {
    {"ISA", Isa, 0},
    {"MCA", MicroChannel, 0},
    {"PCI", PCIBus, 0},
    {"VME", VMEBus, 0},
    {"PCMCIA", PCMCIABus, 0},
    {"CBUS", CBus, 0},
    {"MPIPI", MPIBus, 0},
    {"MPSA", MPSABus, 0},
    {NULL, Internal, 0}
};

static NTSTATUS ArcSetIdentifier(IN PCONFIGURATION_COMPONENT_DATA ComponentData,
				 IN PCHAR IdentifierString)
{
    PCONFIGURATION_COMPONENT Component = &ComponentData->ComponentEntry;

    /* Allocate memory for the identifier */
    SIZE_T IdentifierLength = strlen(IdentifierString) + 1;
    PCHAR Identifier = ExAllocatePool(IdentifierLength);
    if (Identifier == NULL) {
	return STATUS_NO_MEMORY;
    }

    /* Copy the identifier */
    RtlCopyMemory(Identifier, IdentifierString, IdentifierLength);

    /* Set component information */
    Component->IdentifierLength = (ULONG)IdentifierLength;
    Component->Identifier = Identifier;
    return STATUS_SUCCESS;
}

static VOID ArcSetConfigurationData(IN PCONFIGURATION_COMPONENT_DATA ComponentData,
				    IN PCM_PARTIAL_RESOURCE_LIST ResourceList,
				    IN ULONG Size)
{
    /* Set component information */
    ComponentData->ConfigurationData = ResourceList;
    ComponentData->ComponentEntry.ConfigurationDataLength = Size;
}

NTSTATUS ArcCreateSystemKey(OUT PCONFIGURATION_COMPONENT_DATA *SystemNode)
{
    /* Allocate the root */
    PCONFIGURATION_COMPONENT_DATA ArcHwTreeRoot = ExAllocatePool(sizeof(CONFIGURATION_COMPONENT_DATA));
    if (ArcHwTreeRoot == NULL) {
	return STATUS_NO_MEMORY;
    }

    /* Set it up */
    PCONFIGURATION_COMPONENT Component;
    Component = &ArcHwTreeRoot->ComponentEntry;
    Component->Class = SystemClass;
    Component->Type = MaximumType;
    Component->ConfigurationDataLength = 0;
    Component->Identifier = 0;
    Component->IdentifierLength = 0;
    Component->Flags = 0;
    Component->Version = 0;
    Component->Revision = 0;
    Component->Key = 0;
    Component->AffinityMask = 0xFFFFFFFF;

    /* Return the node */
    *SystemNode = ArcHwTreeRoot;
    return STATUS_SUCCESS;
}

static VOID ArcLinkToParent(IN PCONFIGURATION_COMPONENT_DATA Parent,
			    IN PCONFIGURATION_COMPONENT_DATA Child)
{
    PCONFIGURATION_COMPONENT_DATA Sibling;

    /* Get the first sibling */
    Sibling = Parent->Child;

    /* If no sibling exists, then we are the first child */
    if (!Sibling) {
        /* Link us in */
        Parent->Child = Child;
    } else {
        /* Loop each sibling */
        do {
            /* This is now the parent */
            Parent = Sibling;
        } while ((Sibling = Sibling->Sibling));

        /* Found the lowest sibling; mark us as its sibling too */
        Parent->Sibling = Child;
    }
}

NTSTATUS ArcCreateComponentKey(IN PCONFIGURATION_COMPONENT_DATA SystemNode,
			       IN CONFIGURATION_CLASS Class,
			       IN CONFIGURATION_TYPE Type,
			       IN IDENTIFIER_FLAG Flags,
			       IN ULONG Key,
			       IN ULONG Affinity,
			       IN PCHAR IdentifierString,
			       IN PCM_PARTIAL_RESOURCE_LIST ResourceList,
			       IN ULONG Size,
			       OUT PCONFIGURATION_COMPONENT_DATA *ComponentKey)
{
    /* Allocate the node for this component */
    PCONFIGURATION_COMPONENT_DATA ComponentData = ExAllocatePool(sizeof(CONFIGURATION_COMPONENT_DATA));
    if (ComponentData == NULL) {
	return STATUS_NO_MEMORY;
    }

    /* Now save our parent */
    ComponentData->Parent = SystemNode;

    /* Link us to the parent */
    if (SystemNode) {
        ArcLinkToParent(SystemNode, ComponentData);
    }

    /* Set us up */
    PCONFIGURATION_COMPONENT Component;
    Component = &ComponentData->ComponentEntry;
    Component->Class = Class;
    Component->Type = Type;
    Component->Flags = Flags;
    Component->Key = Key;
    Component->AffinityMask = Affinity;

    /* Set identifier */
    NTSTATUS Status = STATUS_SUCCESS;
    if (IdentifierString) {
        Status = ArcSetIdentifier(ComponentData, IdentifierString);
	if (!NT_SUCCESS(Status)) {
	    return Status;
	}
    }

    /* Set configuration data */
    if (ResourceList) {
	ArcSetConfigurationData(ComponentData, ResourceList, Size);
	if (!NT_SUCCESS(Status)) {
	    return Status;
	}
    }

    /* Return the child */
    *ComponentKey = ComponentData;
    return STATUS_SUCCESS;
}

static NTSTATUS ArcInitializeRegistryNode(IN PCONFIGURATION_COMPONENT_DATA CurrentEntry,
					  IN HANDLE NodeHandle,
					  OUT PHANDLE NewHandle,
					  IN INTERFACE_TYPE InterfaceType,
					  IN ULONG BusNumber,
					  IN PUSHORT DeviceIndexTable,
					  OUT PCM_FULL_RESOURCE_DESCRIPTOR ConfigurationData,
					  IN ULONG ConfigurationDataSize)
{
    UNICODE_STRING KeyName, ValueName, ValueData;
    HANDLE KeyHandle = NULL;
    ANSI_STRING TempString;
    CHAR TempBuffer[12];
    WCHAR Buffer[12];
    ULONG Disposition, Length = 0;

    /* Get the component */
    PCONFIGURATION_COMPONENT Component = &CurrentEntry->ComponentEntry;

    /* Set system class components to ARC system type */
    if (Component->Class == SystemClass)
	Component->Type = ArcSystem;

    /* Create a key for the component */
    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes,
			       &CmTypeName[Component->Type],
			       OBJ_CASE_INSENSITIVE, NodeHandle, NULL);
    NTSTATUS Status = NtCreateKey(&KeyHandle,
				  KEY_READ | KEY_WRITE,
				  &ObjectAttributes, 0,
				  NULL, 0, &Disposition);
    if (!NT_SUCCESS(Status)) {
	TRACE_(PNPMGR, "Unable to create key %wZ\n",
	       &CmTypeName[Component->Type]);
	return Status;
    }

    /* Check if this is anything but a system class component */
    if (Component->Class != SystemClass) {
	/* Build the sub-component string */
	RtlIntegerToChar(DeviceIndexTable[Component->Type]++,
			 10, 12, TempBuffer);
	RtlInitAnsiString(&TempString, TempBuffer);

	/* Convert it to Unicode */
	RtlInitEmptyUnicodeString(&KeyName, Buffer, sizeof(Buffer));
	Status = RtlAnsiStringToUnicodeString(&KeyName, &TempString, FALSE);
	if (!NT_SUCCESS(Status)) {
	    goto out;
	}

	/* Create the key */
	HANDLE ParentHandle = KeyHandle;
	InitializeObjectAttributes(&ObjectAttributes,
				   &KeyName,
				   OBJ_CASE_INSENSITIVE,
				   ParentHandle, NULL);
	Status = NtCreateKey(&KeyHandle,
			     KEY_READ | KEY_WRITE,
			     &ObjectAttributes, 0, NULL, 0, &Disposition);
	NtClose(ParentHandle);

	/* Fail if the key couldn't be created, and make sure it's a new key */
	if (!NT_SUCCESS(Status)) {
	    TRACE_(PNPMGR, "Unable to create key %wZ\n", &KeyName);
	    return Status;
	}
	ASSERT(Disposition == REG_CREATED_NEW_KEY);
    }

    /* Setup the component information key */
    RtlInitUnicodeString(&ValueName, L"Component Information");
    Status = NtSetValueKey(KeyHandle,
			   &ValueName,
			   0,
			   REG_BINARY,
			   &Component->Flags,
			   FIELD_OFFSET(CONFIGURATION_COMPONENT, ConfigurationDataLength) -
			   FIELD_OFFSET(CONFIGURATION_COMPONENT, Flags));
    if (!NT_SUCCESS(Status)) {
	goto out;
    }

    /* Check if we have an identifier */
    if (Component->IdentifierLength) {
	/* Build the string and convert it to Unicode */
	RtlInitUnicodeString(&ValueName, L"Identifier");
	RtlInitAnsiString(&TempString, Component->Identifier);
	Status = RtlAnsiStringToUnicodeString(&ValueData,
					      &TempString, TRUE);
	if (!NT_SUCCESS(Status)) {
	    goto out;
	}

	/* Save the identifier in the registry */
	Status = NtSetValueKey(KeyHandle,
			       &ValueName,
			       0,
			       REG_SZ,
			       ValueData.Buffer,
			       ValueData.Length + sizeof(UNICODE_NULL));
	RtlFreeUnicodeString(&ValueData);
	if (!NT_SUCCESS(Status)) {
	    goto out;
	}
    }

    /* Setup the configuration data string */
    RtlInitUnicodeString(&ValueName, L"Configuration Data");

    /* Check if we got configuration data */
    if (CurrentEntry->ConfigurationData) {
	/* Calculate the total length and check if it fits into our buffer */
	Length = Component->ConfigurationDataLength +
	    FIELD_OFFSET(CM_FULL_RESOURCE_DESCRIPTOR, PartialResourceList);
	if (Length > ConfigurationDataSize) {
	    ASSERTMSG("Component too large -- need reallocation!\n",
		      FALSE);
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	    goto out;
	} else {
	    /* Copy the data */
	    RtlCopyMemory(&ConfigurationData->PartialResourceList.Version,
			  CurrentEntry->ConfigurationData,
			  Component->ConfigurationDataLength);
	}
    } else {
	/* No configuration data, setup defaults */
	ConfigurationData->PartialResourceList.Version = 0;
	ConfigurationData->PartialResourceList.Revision = 0;
	ConfigurationData->PartialResourceList.Count = 0;
	Length = FIELD_OFFSET(CM_PARTIAL_RESOURCE_LIST, PartialDescriptors) +
	    FIELD_OFFSET(CM_FULL_RESOURCE_DESCRIPTOR, PartialResourceList);
    }

    /* Set the interface type and bus number */
    ConfigurationData->InterfaceType = InterfaceType;
    ConfigurationData->BusNumber = BusNumber;

    /* Save the actual data */
    Status = NtSetValueKey(KeyHandle,
			   &ValueName,
			   0,
			   REG_FULL_RESOURCE_DESCRIPTOR,
			   ConfigurationData, Length);
out:
    if (!NT_SUCCESS(Status) && KeyHandle != NULL) {
	/* Fail */
	NtClose(KeyHandle);
    } else {
	assert(KeyHandle != NULL);
	/* Return the new handle */
	*NewHandle = KeyHandle;
    }

    /* Return status */
    return Status;
}

static NTSTATUS ArcSetupConfigurationTree(IN PCONFIGURATION_COMPONENT_DATA CurrentEntry,
					  IN HANDLE ParentHandle,
					  IN INTERFACE_TYPE InterfaceType,
					  IN ULONG BusNumber,
					  OUT PCM_FULL_RESOURCE_DESCRIPTOR ConfigurationData,
					  IN ULONG ConfigurationDataSize)
{
    USHORT DeviceIndexTable[MaximumType + 1] = { 0 };
    ULONG Interface = InterfaceType, Bus = BusNumber, i;

    /* Loop each entry */
    while (CurrentEntry) {
	/* Check if this is an adapter */
	PCONFIGURATION_COMPONENT Component = &CurrentEntry->ComponentEntry;
	if ((Component->Class == AdapterClass) &&
	    (CurrentEntry->Parent->ComponentEntry.Class == SystemClass)) {
	    /* Check what kind of adapter it is */
	    switch (Component->Type) {
	    /* EISA */
	    case EisaAdapter:
		/* Fixup information */
		Interface = Eisa;
		break;

	    /* Turbo-channel */
	    case TcAdapter:
		/* Fixup information */
		Interface = TurboChannel;
		break;

	    /* ISA, PCI, etc busses */
	    case MultiFunctionAdapter:
		/* Check if we have an identifier */
		if (Component->Identifier) {
		    /* Loop each multi-function adapter type */
		    for (i = 0; CmpMultifunctionTypes[i].Identifier; i++) {
			/* Check for a name match */
			if (!_stricmp(CmpMultifunctionTypes[i].Identifier,
				     Component->Identifier)) {
			    /* Match found */
			    break;
			}
		    }

		    /* Fix up information */
		    Interface = CmpMultifunctionTypes[i].InterfaceType;
		    Bus = CmpMultifunctionTypes[i].Count++;
		}
		break;

	    /* SCSI Bus */
	    case ScsiAdapter:
		/* Fix up */
		Interface = Internal;
		break;

	    /* Unknown */
	    default:
		Interface = -1;
		break;
	    }
	}

	/* Dump information on the component */

	/* Setup the hardware node */
	HANDLE NewHandle;
	NTSTATUS Status = ArcInitializeRegistryNode(CurrentEntry,
						    ParentHandle,
						    &NewHandle,
						    Interface,
						    Bus,
						    DeviceIndexTable,
						    ConfigurationData,
						    ConfigurationDataSize);
	if (!NT_SUCCESS(Status))
	    return Status;

	/* Check for children */
	if (CurrentEntry->Child) {
	    /* Recursively setup the child tree */
	    Status = ArcSetupConfigurationTree(CurrentEntry->Child,
					       NewHandle, Interface, Bus,
					       ConfigurationData,
					       ConfigurationDataSize);
	    if (!NT_SUCCESS(Status)) {
		NtClose(NewHandle);
		return Status;
	    }
	}

	/* Get to the next entry */
	NtClose(NewHandle);
	CurrentEntry = CurrentEntry->Sibling;
    }

    /* We're done */
    return STATUS_SUCCESS;
}

NTSTATUS ArcSetupHardwareDescriptionDatabase(IN PCONFIGURATION_COMPONENT_DATA ConfigurationRoot)
{
    /* Setup the key name */
    UNICODE_STRING KeyName;
    RtlInitUnicodeString(&KeyName,
			 L"\\Registry\\Machine\\Hardware\\Description");
    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes,
			       &KeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    /* Create the device map key */
    HANDLE KeyHandle;
    ULONG Disposition;
    NTSTATUS Status = NtCreateKey(&KeyHandle,
				  KEY_READ | KEY_WRITE,
				  &ObjectAttributes, 0, NULL, 0, &Disposition);
    if (!NT_SUCCESS(Status))
	return Status;

    /* Nobody should've created this key yet! */
    ASSERT(Disposition == REG_CREATED_NEW_KEY);

    /* Allocate the configuration data buffer */
    ULONG ConfigurationAreaSize = 4 * PAGE_SIZE;
    PCM_FULL_RESOURCE_DESCRIPTOR ConfigurationData = ExAllocatePool(ConfigurationAreaSize);
    if (!ConfigurationData) {
	TRACE_(PNPMGR, "Unable to allocate resource descriptor\n");
	NtClose(KeyHandle);
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Setup the configuration tree */
    Status = ArcSetupConfigurationTree(ConfigurationRoot, KeyHandle, -1, -1,
				       ConfigurationData, ConfigurationAreaSize);

    /* Free the buffer, close our handle and return status */
    ExFreePool(ConfigurationData);
    NtClose(KeyHandle);
    return Status;
}
