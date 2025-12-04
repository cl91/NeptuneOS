#include "cmp.h"

#ifdef CMDBG
#define CmpDbgPrintIndentation RtlDbgPrintIndentation
#else
#define CmpDbgPrintIndentation(...)
#endif

VOID CmpFreeValue(IN PCM_REG_VALUE Value)
{
    assert(Value);
    if (Value->Data) {
	CmpFreePool(Value->Data);
    }
    CmpFreePool(Value);
}

static NTSTATUS CmpSetValueKey(IN PCM_KEY_OBJECT Key,
			       IN PCSTR ValueName,
			       IN ULONG Type,
			       IN PVOID Data,
			       IN ULONG DataSize)
{
    ULONG Utf16DataSize = DataSize;
    if (Type == REG_SZ || Type == REG_MULTI_SZ || Type == REG_LINK || Type == REG_EXPAND_SZ) {
	NTSTATUS Status = RtlUTF8ToUnicodeN(NULL, 0, &Utf16DataSize,
					    Data, DataSize);
	if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_TOO_SMALL) {
	    return Status;
	}
    }

    PCM_NODE Node = CmpGetNamedNode(Key, ValueName, 0);
    if (Node != NULL && Node->Type != CM_NODE_VALUE) {
	return STATUS_OBJECT_TYPE_MISMATCH;
    }
    BOOLEAN NewValue = (Node == NULL);
    PCM_REG_VALUE Value = Node ? CONTAINING_RECORD(Node, CM_REG_VALUE, Node) :
	(PCM_REG_VALUE)ExAllocatePoolWithTag(sizeof(CM_REG_VALUE), NTOS_CM_TAG);
    if (Value == NULL) {
	return STATUS_NO_MEMORY;
    }
    Value->Type = Type;
    switch (Type) {
    case REG_DWORD:
	Value->Dword = *((PULONG)Data);
	break;
    case REG_QWORD:
	Value->Qword = *((PULONGLONG)Data);
	break;
    case REG_SZ:
    case REG_BINARY:
    case REG_LINK:
    case REG_MULTI_SZ:
    case REG_EXPAND_SZ:
    case REG_FULL_RESOURCE_DESCRIPTOR:
	assert(DataSize != 0);
	PVOID SavedData = ExAllocatePoolWithTag(DataSize, NTOS_CM_TAG);
	if (SavedData == NULL) {
	    if (NewValue) {
		CmpFreePool(Value);
	    }
	    return STATUS_NO_MEMORY;
	}
	Value->Data = SavedData;
	Value->DataSize = DataSize;
	Value->Utf16DataSize = Utf16DataSize;
	memcpy(Value->Data, Data, DataSize);
	break;
    default:
	UNIMPLEMENTED;
    }
    if (NewValue) {
	Value->Node.Type = CM_NODE_VALUE;
	RET_ERR_EX(CmpInsertNamedNode(Key, &Value->Node, ValueName),
		   CmpFreeValue(Value));
	/* Increase the refcount of the key so it won't be deleted
	 * until all values are deleted. */
	ObpReferenceObject(Key);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS CmpMarshalValueData(IN PCM_REG_VALUE Value,
				    IN PVOID InfoBuffer,
				    IN ULONG DataOffset,
				    IN BOOLEAN Utf16)
{
    CmDbg("Marshaling value data for value %s data type %d\n",
	  Value->Node.Name, Value->Type);
    PVOID Data = (PCHAR)InfoBuffer + DataOffset;
    switch (Value->Type) {
    case REG_NONE:
	break;
    case REG_DWORD:
	*(PULONG)Data = Value->Dword;
	break;
    case REG_QWORD:
	*(PULONG)Data = Value->Qword;
	break;
    case REG_SZ:
    case REG_EXPAND_SZ:
    case REG_LINK:
    case REG_MULTI_SZ:
	if (Utf16) {
	    UNUSED ULONG BytesWritten = 0;
	    RET_ERR(RtlUTF8ToUnicodeN(Data, Value->Utf16DataSize, &BytesWritten,
				      Value->Data, Value->DataSize));
	    assert(Value->Utf16DataSize == BytesWritten);
	} else {
	    memcpy(Data, Value->Data, Value->DataSize);
	}
	break;
    case REG_BINARY:
    case REG_RESOURCE_LIST:
    case REG_FULL_RESOURCE_DESCRIPTOR:
    case REG_RESOURCE_REQUIREMENTS_LIST:
	memcpy(Data, Value->Data, Value->DataSize);
	break;
    default:
	UNIMPLEMENTED;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS CmpQueryValueKey(IN PCM_KEY_OBJECT Key,
				 IN PCSTR ValueName,
				 IN KEY_VALUE_INFORMATION_CLASS InfoClass,
				 IN PVOID OutputBuffer,
				 IN ULONG BufferSize,
				 OUT ULONG *ResultLength,
				 IN BOOLEAN Utf16)
{
    assert(ResultLength != NULL);
    PCM_NODE Node = CmpGetNamedNode(Key, ValueName, 0);
    if (Node == NULL) {
	return STATUS_OBJECT_NAME_NOT_FOUND;
    } else if (Node->Type != CM_NODE_VALUE) {
	return STATUS_OBJECT_TYPE_MISMATCH;
    }
#ifdef _WIN64
    /* On 64-bit, always align to 8 bytes */
    ULONG Alignment = 8;
#else
    ULONG Alignment;
    /* On 32-bit, align the offset to 4 or 8 bytes */
    if (InfoClass == KeyValueFullInformationAlign64 ||
	InfoClass == KeyValuePartialInformationAlign64) {
	Alignment = 8;
    } else {
	Alignment = 4;
    }
#endif

    PCM_REG_VALUE Value = (PCM_REG_VALUE)Node;
    switch (InfoClass) {
    case KeyValueBasicInformation:
    {
	PKEY_VALUE_BASIC_INFORMATION Info = (PKEY_VALUE_BASIC_INFORMATION)OutputBuffer;
	*ResultLength = sizeof(KEY_VALUE_BASIC_INFORMATION) +
	    (Utf16 ? Value->Node.Utf16NameLength : (Value->Node.NameLength + 1));
	if (BufferSize < *ResultLength) {
	    CmDbg("Need buffer size 0x%x got 0x%x\n", *ResultLength, BufferSize);
	    return STATUS_BUFFER_TOO_SMALL;
	}
	Info->TitleIndex = 0;
	Info->Type = Value->Type;
	if (Utf16) {
	    UNUSED ULONG Unused = 0;
	    RET_ERR(RtlUTF8ToUnicodeN(Info->Name, Value->Node.Utf16NameLength,
				      &Unused, Value->Node.Name, Value->Node.NameLength));
	} else {
	    memcpy(Info->Name, Value->Node.Name, Value->Node.NameLength + 1);
	}
    }
    break;

    case KeyValueFullInformation:
    case KeyValueFullInformationAlign64:
    {
	PKEY_VALUE_FULL_INFORMATION Info = (PKEY_VALUE_FULL_INFORMATION)OutputBuffer;
	ULONG NameOffset = ALIGN_UP_BY(sizeof(KEY_VALUE_FULL_INFORMATION), Alignment);
	ULONG NameLength = Utf16 ? Value->Node.Utf16NameLength : (Value->Node.NameLength + 1);
	ULONG DataOffset = NameOffset + ALIGN_UP_BY(NameLength, Alignment);
	ULONG DataLength = CmpGetValueDataLength(Value, Utf16);
	*ResultLength = DataOffset + DataLength;
	if (BufferSize < *ResultLength) {
	    CmDbg("Need buffer size 0x%x got 0x%x\n", *ResultLength, BufferSize);
	    return STATUS_BUFFER_TOO_SMALL;
	}
	Info->TitleIndex = 0;
	Info->Type = Value->Type;
	Info->DataOffset = DataOffset;
	Info->DataLength = DataLength;
	Info->NameLength = NameLength;
	if (Utf16) {
	    RET_ERR(RtlUTF8ToUnicodeN((PWSTR)((PCHAR)Info + NameOffset),
				      Value->Node.Utf16NameLength, &NameLength,
				      Value->Node.Name, Value->Node.NameLength));
	    assert(NameLength == Value->Node.Utf16NameLength);
	} else {
	    memcpy((PCHAR)Info + NameOffset, Value->Node.Name, Value->Node.NameLength + 1);
	}
	RET_ERR(CmpMarshalValueData(Value, Info, DataOffset, Utf16));
    }
    break;

    case KeyValuePartialInformation:
    {
	PKEY_VALUE_PARTIAL_INFORMATION Info = (PKEY_VALUE_PARTIAL_INFORMATION)OutputBuffer;
	ULONG DataOffset = sizeof(KEY_VALUE_PARTIAL_INFORMATION);
	ULONG DataLength = CmpGetValueDataLength(Value, Utf16);
	*ResultLength = DataOffset + DataLength;
	if (BufferSize < *ResultLength) {
	    CmDbg("Need buffer size 0x%x got 0x%x\n", *ResultLength, BufferSize);
	    return STATUS_BUFFER_TOO_SMALL;
	}
	Info->TitleIndex = 0;
	Info->Type = Value->Type;
	Info->DataLength = DataLength;
	RET_ERR(CmpMarshalValueData(Value, Info, DataOffset, Utf16));
    }
    break;

    case KeyValuePartialInformationAlign64:
    {
	PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64 Info =
	    (PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64)OutputBuffer;
	ULONG DataOffset = sizeof(KEY_VALUE_PARTIAL_INFORMATION_ALIGN64);
	ULONG DataLength = CmpGetValueDataLength(Value, Utf16);
	*ResultLength = DataOffset + DataLength;
	if (BufferSize < *ResultLength) {
	    CmDbg("Need buffer size 0x%x got 0x%x\n", *ResultLength, BufferSize);
	    return STATUS_BUFFER_TOO_SMALL;
	}
	Info->Type = Value->Type;
	Info->DataLength = DataLength;
	RET_ERR(CmpMarshalValueData(Value, Info, DataOffset, Utf16));
    }
    break;

    default:
	/* We got some class that we don't support */
	DPRINT1("Caller requested unknown class: %d\n", InfoClass);
	return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

/*
 * Load the registry key from disk and return the specified value under
 * the key, as well as the key object itself.
 *
 * NOTE: This routine returns a pointer into the in-memory registry data.
 * You must call ObDereferenceObject on the key object once you are done
 * with the value.
 */
NTSTATUS CmReadKeyValueByPath(IN ASYNC_STATE State,
			      IN PTHREAD Thread,
			      IN PCSTR KeyPath,
			      IN PCSTR Value,
			      OUT POBJECT *KeyObject,
			      OUT ULONG *Type,
			      OUT PVOID *Data)
{
    /* TODO: Load the registry key from disk. */

    *KeyObject = NULL;
    PCM_KEY_OBJECT Key = NULL;
    RET_ERR(ObReferenceObjectByName(KeyPath, OBJECT_TYPE_KEY,
				    NULL, FALSE, (POBJECT *)&Key));
    assert(Key);
    CmpDbgDumpKey(Key);
    RET_ERR_EX(CmReadKeyValueByPointer(Key, Value, Type, Data),
	       ObDereferenceObject(Key));
    *KeyObject = Key;
    return STATUS_SUCCESS;
}

NTSTATUS CmReadKeyValueByPointer(IN POBJECT KeyObject,
				 IN PCSTR Value,
				 OUT ULONG *Type,
				 OUT PVOID *Data)
{
    if (!ObObjectIsType(KeyObject, OBJECT_TYPE_KEY)) {
	return STATUS_OBJECT_TYPE_MISMATCH;
    }
    PCM_NODE Node = CmpGetNamedNode(KeyObject, Value, 0);
    if (Node == NULL || Node->Type != CM_NODE_VALUE) {
	return Node == NULL ? STATUS_OBJECT_NAME_NOT_FOUND : STATUS_OBJECT_TYPE_MISMATCH;
    }
    PCM_REG_VALUE ValueObj = (PCM_REG_VALUE)Node;
#ifdef _M_IX86
    assert(ValueObj->Type != REG_QWORD);
#endif
    *Type = ValueObj->Type;
    *Data = ValueObj->Data;
    return STATUS_SUCCESS;
}

#ifdef CMDBG
static PCSTR CmpDbgInterfaceTypes[] = {
    "Internal",
    "Isa",
    "Eisa",
    "MicroChannel",
    "TurboChannel",
    "PCIBus",
    "VMEBus",
    "NuBus",
    "PCMCIABus",
    "CBus",
    "MPIBus",
    "MPSABus",
    "ProcessorInternal",
    "InternalPowerBus",
    "PNPISABus",
    "PNPBus",
    "MaximumInterfaceType"
};

static PCSTR CmpDbgInterfaceTypeToStr(IN INTERFACE_TYPE Type)
{
    if (Type <= 0 || Type > MaximumInterfaceType) {
	return "Undefined";
    }
    return CmpDbgInterfaceTypes[Type];
}
#endif

static VOID CmpDbgDumpPartialResourceDescriptor(IN PCM_PARTIAL_RESOURCE_DESCRIPTOR Desc,
						IN ULONG Indent)
{
    CmpDbgPrintIndentation(Indent);
    CmDbgPrint("TYPE %d SHARE-DISPOSITION %d FLAGS 0x%x\n",
	       Desc->Type, Desc->ShareDisposition, Desc->Flags);
    CmpDbgPrintIndentation(Indent + 2);
    switch (Desc->Type) {
    case CmResourceTypeNull:
	CmDbgPrint("NULL-RESOURCE\n");
	break;
    case CmResourceTypePort:
	CmDbgPrint("PORT Start 0x%llx Length 0x%x\n",
		   Desc->Port.Start.QuadPart, Desc->Port.Length);
	break;
    case CmResourceTypeInterrupt:
	CmDbgPrint("INTERRUPT Level 0x%x Vector 0x%x Affinity 0x%zx\n",
		   Desc->Interrupt.Level, Desc->Interrupt.Vector,
		   (MWORD)Desc->Interrupt.Affinity);
	break;
    case CmResourceTypeMemory:
	CmDbgPrint("MEMORY Start 0x%llx Length 0x%x\n",
		   Desc->Memory.Start.QuadPart, Desc->Memory.Length);
	break;
    case CmResourceTypeDma:
	CmDbgPrint("DMA Channel 0x%x Port 0x%x Reserved1 0x%x\n",
		   Desc->Dma.Channel, Desc->Dma.Port,
		   Desc->Dma.Reserved1);
	break;
    case CmResourceTypeDeviceSpecific:
	CmDbgPrint("DEVICE-SPECIFIC DataSize 0x%x Reserved1 0x%x Reserved2 0x%x\n",
		   Desc->DeviceSpecificData.DataSize,
		   Desc->DeviceSpecificData.Reserved1,
		   Desc->DeviceSpecificData.Reserved2);
	break;
    case CmResourceTypeBusNumber:
	CmDbgPrint("BUS-NUMBER Start 0x%x Length 0x%x Reserved 0x%x\n",
		   Desc->BusNumber.Start, Desc->BusNumber.Length,
		   Desc->BusNumber.Reserved);
	break;
    case CmResourceTypeMemoryLarge:
	CmDbgPrint("MEMORY-LARGE\n");
	break;
    case CmResourceTypeConfigData:
	CmDbgPrint("CONFIG-DATA\n");
	break;
    case CmResourceTypeDevicePrivate:
	CmDbgPrint("DEVICE-PRIVATE\n");
	break;
    case CmResourceTypePcCardConfig:
	CmDbgPrint("PC-CARD-CONFIG\n");
	break;
    case CmResourceTypeMfCardConfig:
	CmDbgPrint("MF-CARD-CONFIG\n");
	break;
    }
}

static VOID CmpDbgDumpFullResourceDescriptor(IN PCM_FULL_RESOURCE_DESCRIPTOR Desc,
					     IN ULONG Indent)
{
    CmpDbgPrintIndentation(Indent);
    CmDbgPrint("INTERFACE-TYPE %s BUS-NUMBER %d\n",
	       CmpDbgInterfaceTypeToStr(Desc->InterfaceType), Desc->BusNumber);
    CmpDbgPrintIndentation(Indent);
    CmDbgPrint("PARTIAL-RESOURCE-LIST Version %d Revision %d Count %d\n",
	       Desc->PartialResourceList.Version,
	       Desc->PartialResourceList.Revision,
	       Desc->PartialResourceList.Count);
    for (ULONG i = 0; i < Desc->PartialResourceList.Count; i++) {
	CmpDbgDumpPartialResourceDescriptor(&Desc->PartialResourceList.PartialDescriptors[i],
					    Indent + 2);
    }
}

VOID CmpDbgDumpValue(IN PCM_REG_VALUE Value)
{
    CmDbgPrint("  VALUE ");
    CmpDbgDumpNode(&Value->Node);
    CmDbgPrint("  ");
    switch (Value->Type) {
    case REG_NONE:
	CmDbgPrint("TYPE REG_NONE\n");
	break;
    case REG_SZ:
	CmDbgPrint("TYPE REG_SZ DATA %s\n", (PCSTR)Value->Data);
	break;
    case REG_EXPAND_SZ:
	CmDbgPrint("TYPE REG_EXPAND_SZ DATA %s\n", (PCSTR)Value->Data);
	break;
    case REG_BINARY:
	CmDbgPrint("TYPE REG_BINARY DATA-PTR %p\n", Value->Data);
	break;
    case REG_DWORD:
	CmDbgPrint("TYPE REG_DWORD DATA 0x%x\n", Value->Dword);
	break;
    case REG_DWORD_BIG_ENDIAN:
	CmDbgPrint("TYPE REG_DWORD_BIG_ENDIAN\n");
	break;
    case REG_LINK:
	CmDbgPrint("TYPE REG_LINK DATA %s\n", (PCSTR)Value->Data);
	break;
    case REG_MULTI_SZ:
	CmDbgPrint("TYPE REG_MULTI_SZ\n");
	break;
    case REG_RESOURCE_LIST:
    {
	PCM_RESOURCE_LIST ResList = (PCM_RESOURCE_LIST)Value->Data;
	CmDbgPrint("TYPE REG_RESOURCE_LIST Count %d\n",
		   ResList->Count);
	for (ULONG i = 0; i < ResList->Count; i++) {
	    CmpDbgDumpFullResourceDescriptor(&ResList->List[i], 6);
	}
    }
    break;
    case REG_FULL_RESOURCE_DESCRIPTOR:
	CmDbgPrint("TYPE REG_FULL_RESOURCE_DESCRIPTOR\n");
	CmpDbgDumpFullResourceDescriptor((PCM_FULL_RESOURCE_DESCRIPTOR)Value->Data, 6);
	break;
    case REG_RESOURCE_REQUIREMENTS_LIST:
	CmDbgPrint("TYPE REG_RESOURCE_REQUIREMENTS_LIST\n");
	break;
    case REG_QWORD:
	CmDbgPrint("TYPE REG_QWORD DATA 0x%llx\n", Value->Qword);
	break;
    default:
	CmDbgPrint("TYPE UNKNOWN\n");
    }
}

/*
 * This corresponds to the NtQueryValueKey stub routine in the client-side.
 * Note that as opposed to the server-side NtQueryValueKeyA function below,
 * the output here is in UTF-16LE.
 */
NTSTATUS NtQueryValueKeyW(IN ASYNC_STATE AsyncState,
			  IN PTHREAD Thread,
			  IN HANDLE KeyHandle,
			  IN PCSTR ValueName,
			  IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
			  IN PVOID OutputBuffer,
			  IN ULONG BufferSize,
			  OUT ULONG *ResultLength)
{
    CmDbg("Querying value %s for key handle %p KVIC %x bufsize 0x%x\n",
	  ValueName, KeyHandle, KeyValueInformationClass, BufferSize);
    assert(Thread->Process != NULL);
    if ((KeyValueInformationClass == KeyValueFullInformationAlign64 ||
	 KeyValueInformationClass == KeyValuePartialInformationAlign64)
	&& (ALIGN_DOWN_POINTER(OutputBuffer, ULONGLONG) != OutputBuffer)) {
	return STATUS_DATATYPE_MISALIGNMENT;
    }
    PCM_KEY_OBJECT Key = NULL;
    RET_ERR(ObReferenceObjectByHandle(Thread, KeyHandle,
				      OBJECT_TYPE_KEY, (POBJECT *)&Key));
    assert(Key != NULL);
    CmpDbgDumpKey(Key);
    NTSTATUS Status = CmpQueryValueKey(Key, ValueName,
				       KeyValueInformationClass,
				       OutputBuffer, BufferSize,
				       ResultLength, TRUE);
    ObDereferenceObject(Key);
    return Status;
}

/*
 * This corresponds to the NtQueryValueKeyA stub routine on the client-side.
 * Output here is in UTF-8.
 */
NTSTATUS NtQueryValueKeyA(IN ASYNC_STATE AsyncState,
			  IN PTHREAD Thread,
			  IN HANDLE KeyHandle,
			  IN PCSTR ValueName,
			  IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
			  IN PVOID OutputBuffer,
			  IN ULONG BufferSize,
			  OUT ULONG *ResultLength)
{
    CmDbg("Querying value %s for key handle %p KVIC %x bufsize 0x%x\n",
	  ValueName, KeyHandle, KeyValueInformationClass, BufferSize);
    assert(Thread->Process != NULL);
    if ((KeyValueInformationClass == KeyValueFullInformationAlign64 ||
	 KeyValueInformationClass == KeyValuePartialInformationAlign64)
	&& (ALIGN_DOWN_POINTER(OutputBuffer, ULONGLONG) != OutputBuffer)) {
	return STATUS_DATATYPE_MISALIGNMENT;
    }
    PCM_KEY_OBJECT Key = NULL;
    RET_ERR(ObReferenceObjectByHandle(Thread, KeyHandle,
				      OBJECT_TYPE_KEY, (POBJECT *)&Key));
    assert(Key != NULL);
    NTSTATUS Status = CmpQueryValueKey(Key, ValueName,
				       KeyValueInformationClass,
				       OutputBuffer, BufferSize,
				       ResultLength, FALSE);
    ObDereferenceObject(Key);
    return Status;
}

/*
 * This is the server-side handler for NtSetValueKey.
 *
 * This routine expects that the input data is correctly marshaled by
 * the client dll (ntdll.dll), in particular when it comes to variable
 * length data. See ntdll/ke/service.c for details.
 *
 * The reason for this design is that MmMapUserBuffer needs to know
 * the exact DataSize of the input data, otherwise it would not be
 * able to fully map the user buffer into server address space. The
 * mapping is invoked automatically by the parameter marshaling and
 * unmarshaling code generated by syssvc-gen.py.
 */
NTSTATUS NtSetValueKey(IN ASYNC_STATE AsyncState,
                       IN PTHREAD Thread,
                       IN HANDLE KeyHandle,
                       IN PCSTR ValueName,
                       IN ULONG TitleIndex,
                       IN ULONG Type,
                       IN PVOID Data,
                       IN ULONG DataSize)
{
    /* On client side we marshal the REG_SZ and REG_MULTI_SZ and supply
     * a non-zero DataSize to the server. */
    CmDbg("Setting value %s of key handle %p\n", ValueName, KeyHandle);
    if (DataSize == 0) {
	CmDbg("Invalid data size (data size cannot be zero).\n");
	return STATUS_INVALID_PARAMETER;
    }
    if ((Type == REG_DWORD || Type == REG_DWORD_BIG_ENDIAN) &&
	(DataSize != sizeof(ULONG))) {
	CmDbg("Expected data size 0x%zx got data size 0x%x.\n",
	      sizeof(ULONG), DataSize);
	return STATUS_INVALID_PARAMETER;
    }
    if (Type == REG_QWORD && DataSize != sizeof(ULONGLONG)) {
	CmDbg("Expected data size 0x%zx got data size 0x%x.\n",
	      sizeof(ULONGLONG), DataSize);
	return STATUS_INVALID_PARAMETER;
    }
    assert(Thread->Process != NULL);
    PCM_KEY_OBJECT Key = NULL;
    RET_ERR(ObReferenceObjectByHandle(Thread, KeyHandle,
				      OBJECT_TYPE_KEY, (POBJECT *)&Key));
    assert(Key != NULL);
    assert(Data != NULL);
    RET_ERR_EX(CmpSetValueKey(Key, ValueName, Type, Data, DataSize),
	       {
		   ObDereferenceObject(Key);
	       });
    CmpDbgDumpKey(Key);
    ObDereferenceObject(Key);
    return STATUS_SUCCESS;
}

NTSTATUS NtEnumerateValueKey(IN ASYNC_STATE AsyncState,
                             IN PTHREAD Thread,
                             IN HANDLE KeyHandle,
                             IN ULONG Index,
                             IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
                             IN PVOID InformationBuffer,
                             IN ULONG BufferSize,
                             OUT ULONG *ResultLength)
{
    UNIMPLEMENTED;
}

NTSTATUS NtDeleteValueKey(IN ASYNC_STATE AsyncState,
                          IN PTHREAD Thread,
                          IN HANDLE KeyHandle,
                          IN PCSTR ValueName)
{
    UNIMPLEMENTED;
}
