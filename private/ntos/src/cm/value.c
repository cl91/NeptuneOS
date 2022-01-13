#include "cmp.h"

static NTSTATUS CmpSetValueKey(IN PCM_KEY_OBJECT Key,
			       IN PCSTR ValueName,
			       IN ULONG Type,
			       IN PVOID Data,
			       IN ULONG DataSize)
{
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
	assert(DataSize != 0);
	PVOID SavedData = ExAllocatePoolWithTag(DataSize, NTOS_CM_TAG);
	if (SavedData == NULL) {
	    if (NewValue) {
		ExFreePool(Value);
	    }
	    return STATUS_NO_MEMORY;
	}
	Value->Data = SavedData;
	Value->DataSize = DataSize;
	memcpy(Value->Data, Data, DataSize);
	break;
    default:
	UNIMPLEMENTED;
    }
    if (NewValue) {
	Value->Node.Type = CM_NODE_VALUE;
	RET_ERR_EX(CmpInsertNamedNode(Key, &Value->Node, ValueName, 0),
		   ExFreePool(Value));
    }
    return STATUS_SUCCESS;
}

/*
 * Marshal the given UTF-8 string into UTF-16LE string. If the input
 * string is NUL-terminated, the output string will also be, and vice
 * versa.
 *
 * @param String
 *   UTF-8 string to be marshaled.
 * @param StringSize
 *   Size of the UTF-8 string in bytes, including the terminating NUL.
 *   If zero, this routine will calculate StringSize using strlen.
 * @param InfoBuffer
 *   Start of the KEY_VALUE_INFORMATION buffer
 * @param CurrentOffset
 *   Pointer to the current data offset. If alignment is specified,
 *   *CurrentOffset will be aligned up by the given alignment. The
 *   aligned data offset is returned via the same argument.
 * @param DataLength
 *   Length of the resulting UTF-16LE string, including the terminating
 *   NUL if the input is NUL-terminated.
 * @param BufferSize
 *   Size of the KEY_VALUE_INFORMATION buffer. This routine will not
 *   write more than BufferSize bytes.
 * @param Alignment
 *   If not zero, specifies the alignment of the start of the marshaled
 *   data. Alignment can only be 4 or 8.
 */
static NTSTATUS CmpMarshalString(IN PCSTR String,
				 IN OPTIONAL ULONG StringSize,
				 IN PVOID InfoBuffer,
				 IN OUT ULONG *CurrentOffset,
				 OUT ULONG *DataLength,
				 IN ULONG BufferSize,
				 IN OPTIONAL ULONG Alignment)
{
    DbgTrace("Marshaling string %s Info BufferSize is 0x%x *CurrentOffset 0x%x\n",
	     String, BufferSize, *CurrentOffset);
    assert(Alignment == 0 || Alignment == 4 || Alignment == 8);
    if (Alignment != 0) {
	*CurrentOffset = ALIGN_UP_BY(*CurrentOffset, Alignment);
    }
    if (*CurrentOffset >= BufferSize) {
	return STATUS_BUFFER_TOO_SMALL;
    }
    if (StringSize == 0) {
	StringSize = strlen(String) + 1;
    }
    return RtlUTF8ToUnicodeN((PWSTR)((PCHAR)InfoBuffer + *CurrentOffset),
			     BufferSize - *CurrentOffset, DataLength,
			     String, StringSize);
}

static NTSTATUS CmpMarshalValueData(IN PCM_REG_VALUE Value,
				    IN PVOID InfoBuffer,
				    IN OUT ULONG *CurrentOffset,
				    OUT ULONG *DataLength,
				    IN ULONG BufferSize,
				    IN OPTIONAL ULONG Alignment)
{
    DbgTrace("Marshaling value data for value %s data type %d\n",
	     Value->Node.Name, Value->Type);
    assert(Alignment == 0 || Alignment == 4 || Alignment == 8);
    if (Alignment != 0) {
	*CurrentOffset = ALIGN_UP_BY(*CurrentOffset, Alignment);
    }
    if (*CurrentOffset >= BufferSize) {
	return STATUS_BUFFER_TOO_SMALL;
    }

    switch (Value->Type) {
    case REG_DWORD:
	if (BufferSize - *CurrentOffset < sizeof(ULONG)) {
	    return STATUS_BUFFER_TOO_SMALL;
	}
	*(PULONG)((ULONG_PTR)InfoBuffer + *CurrentOffset) = Value->Dword;
	break;
    case REG_QWORD:
	if (BufferSize - *CurrentOffset < sizeof(ULONGLONG)) {
	    return STATUS_BUFFER_TOO_SMALL;
	}
	*(PULONG)((ULONG_PTR)InfoBuffer + *CurrentOffset) = Value->Qword;
	break;
    case REG_SZ:
    case REG_EXPAND_SZ:
    case REG_LINK:
    case REG_MULTI_SZ:
	RET_ERR(CmpMarshalString((PCSTR)Value->Data, Value->DataSize,
				 InfoBuffer, CurrentOffset, DataLength,
				 BufferSize, 0));
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
				 OUT OPTIONAL ULONG *pResultLength)
{
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
    ULONG ResultLength = 0;
    switch (InfoClass) {
    case KeyValueBasicInformation:
    {
	PKEY_VALUE_BASIC_INFORMATION Info = (PKEY_VALUE_BASIC_INFORMATION)OutputBuffer;
	if (BufferSize <= sizeof(KEY_VALUE_BASIC_INFORMATION)) {
	    return STATUS_BUFFER_TOO_SMALL;
	}
	ULONG NameStart = sizeof(KEY_VALUE_BASIC_INFORMATION);
	Info->TitleIndex = 0;
	Info->Type = Value->Type;
	RET_ERR(CmpMarshalString(Value->Node.Name, 0, Info, &NameStart,
				 &Info->NameLength, BufferSize, 0));
	ResultLength = NameStart + Info->NameLength;
    }
    break;

    case KeyValueFullInformation:
    case KeyValueFullInformationAlign64:
    {
	PKEY_VALUE_FULL_INFORMATION Info = (PKEY_VALUE_FULL_INFORMATION)OutputBuffer;
	if (BufferSize <= sizeof(KEY_VALUE_FULL_INFORMATION)) {
	    return STATUS_BUFFER_TOO_SMALL;
	}
	ULONG DataOffset = sizeof(KEY_VALUE_FULL_INFORMATION);
	Info->TitleIndex = 0;
	Info->Type = Value->Type;
	RET_ERR(CmpMarshalString(Value->Node.Name, 0, Info, &DataOffset,
				 &Info->NameLength, BufferSize, Alignment));
	DataOffset += Info->NameLength;
	assert(DataOffset <= BufferSize);
	if (DataOffset >= BufferSize) {
	    return STATUS_BUFFER_TOO_SMALL;
	}
	RET_ERR(CmpMarshalValueData(Value, Info, &DataOffset, &Info->DataLength,
				    BufferSize, Alignment));
	ResultLength = DataOffset + Info->DataLength;
    }
    break;

    case KeyValuePartialInformation:
    {
	PKEY_VALUE_PARTIAL_INFORMATION Info = (PKEY_VALUE_PARTIAL_INFORMATION)OutputBuffer;
	if (BufferSize <= sizeof(KEY_VALUE_PARTIAL_INFORMATION)) {
	    return STATUS_BUFFER_TOO_SMALL;
	}
	ULONG DataOffset = sizeof(KEY_VALUE_PARTIAL_INFORMATION);
	Info->TitleIndex = 0;
	Info->Type = Value->Type;
	RET_ERR(CmpMarshalValueData(Value, Info, &DataOffset, &Info->DataLength,
				    BufferSize, Alignment));
	ResultLength = DataOffset + Info->DataLength;
    }
    break;

    case KeyValuePartialInformationAlign64:
    {
	PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64 Info =
	    (PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64)OutputBuffer;
	if (BufferSize <= sizeof(KEY_VALUE_PARTIAL_INFORMATION_ALIGN64)) {
	    return STATUS_BUFFER_TOO_SMALL;
	}
	ULONG DataOffset = sizeof(KEY_VALUE_PARTIAL_INFORMATION_ALIGN64);
	Info->Type = Value->Type;
	RET_ERR(CmpMarshalValueData(Value, Info, &DataOffset, &Info->DataLength,
				    BufferSize, Alignment));
	ResultLength = DataOffset + Info->DataLength;
    }
    break;

    default:
	/* We got some class that we don't support */
	DPRINT1("Caller requested unknown class: %d\n", InfoClass);
	return STATUS_INVALID_PARAMETER;
    }
    return STATUS_SUCCESS;
}

NTSTATUS CmReadKeyValue(IN PCSTR KeyPath,
			IN PCSTR Value,
			OUT POBJECT *KeyObject,
			OUT ULONG *Type,
			OUT PVOID *Data)
{
    PCM_KEY_OBJECT Key = NULL;
    RET_ERR(ObReferenceObjectByName(KeyPath, OBJECT_TYPE_KEY, NULL, (POBJECT *)&Key));
    assert(Key != NULL);
    CmpDbgDumpKey(Key);
    PCM_NODE Node = CmpGetNamedNode(Key, Value, 0);
    if (Node == NULL || Node->Type != CM_NODE_VALUE) {
	ObDereferenceObject(Key);
	return Node == NULL ? STATUS_OBJECT_NAME_NOT_FOUND : STATUS_OBJECT_TYPE_MISMATCH;
    }
    PCM_REG_VALUE ValueObj = (PCM_REG_VALUE)Node;
#ifdef _M_IX86
    assert(ValueObj->Type != REG_QWORD);
#endif
    *KeyObject = Key;
    *Type = ValueObj->Type;
    *Data = ValueObj->Data;
    return STATUS_SUCCESS;
}

VOID CmpDbgDumpValue(IN PCM_REG_VALUE Value)
{
    switch (Value->Type) {
    case REG_NONE:
	DbgPrint("TYPE REG_NONE\n");
	break;
    case REG_SZ:
	DbgPrint("TYPE REG_SZ DATA %s\n", (PCSTR)Value->Data);
	break;
    case REG_EXPAND_SZ:
	DbgPrint("TYPE REG_EXPAND_SZ DATA %s\n", (PCSTR)Value->Data);
	break;
    case REG_BINARY:
	DbgPrint("TYPE REG_BINARY DATA %p\n", Value->Data);
	break;
    case REG_DWORD:
	DbgPrint("TYPE REG_DWORD DATA 0x%x\n", Value->Dword);
	break;
    case REG_DWORD_BIG_ENDIAN:
	DbgPrint("TYPE REG_DWORD_BIG_ENDIAN\n");
	break;
    case REG_LINK:
	DbgPrint("TYPE REG_LINK DATA %s\n", (PCSTR)Value->Data);
	break;
    case REG_MULTI_SZ:
	DbgPrint("TYPE REG_MULTI_SZ\n");
	break;
    case REG_RESOURCE_LIST:
	DbgPrint("TYPE REG_RESOURCE_LIST\n");
	break;
    case REG_FULL_RESOURCE_DESCRIPTOR:
	DbgPrint("TYPE REG_FULL_RESOURCE_DESCRIPTOR\n");
	break;
    case REG_RESOURCE_REQUIREMENTS_LIST:
	DbgPrint("TYPE REG_RESOURCE_REQUIREMENTS_LIST\n");
	break;
    case REG_QWORD:
	DbgPrint("TYPE REG_QWORD DATA 0x%llx\n", Value->Qword);
	break;
    default:
	DbgPrint("TYPE UNKNOWN!\n");
    }
}

/*
 * Note that here as opposed to CmSetKeyValue the output is in UTF-16LE.
 */
NTSTATUS NtQueryValueKey(IN ASYNC_STATE AsyncState,
                         IN PTHREAD Thread,
                         IN HANDLE KeyHandle,
                         IN PCSTR ValueName,
                         IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
                         IN PVOID OutputBuffer,
                         IN ULONG BufferSize,
                         OUT ULONG *ResultLength)
{
    DbgTrace("Querying value %s for key handle %p\n", ValueName, KeyHandle);
    if (BufferSize == 0) {
	return STATUS_INVALID_PARAMETER;
    }
    if (KeyValueInformationClass == KeyValueFullInformationAlign64 ||
	KeyValueInformationClass == KeyValuePartialInformationAlign64) {
	if (ALIGN_DOWN_POINTER(OutputBuffer, ULONGLONG) != OutputBuffer) {
	    return STATUS_DATATYPE_MISALIGNMENT;
	}
    }
    assert(Thread->Process != NULL);
    PCM_KEY_OBJECT Key = NULL;
    RET_ERR(ObReferenceObjectByHandle(Thread->Process, KeyHandle,
				      OBJECT_TYPE_KEY, (POBJECT *)&Key));
    assert(Key != NULL);
    PVOID Data = NULL;
    RET_ERR_EX(MmMapUserBuffer(&Thread->Process->VSpace,
			       (MWORD)OutputBuffer, BufferSize, &Data),
	       ObDereferenceObject(Key));
    assert(Data != NULL);
    RET_ERR_EX(CmpQueryValueKey(Key, ValueName, KeyValueInformationClass,
				Data, BufferSize, ResultLength),
	       {
		   ObDereferenceObject(Key);
		   MmUnmapUserBuffer(Data);
	       });
    ObDereferenceObject(Key);
    MmUnmapUserBuffer(Data);
    return STATUS_SUCCESS;
}

/*
 * This is the server-side handler for NtSetValueKey.
 *
 * This routine expects that the input data is correctly marshaled by
 * the client dll (ntdll.dll), in particular when it comes to variable
 * length data. See ntdll/cm/reg.c for details.
 *
 * The reason for this design is that MmMapUserBuffer(RO) needs to
 * know the exact DataSize of the input data, otherwise it would not
 * be able to fully map the user buffer into server address space.
 */
NTSTATUS CmSetValueKey(IN ASYNC_STATE AsyncState,
                       IN PTHREAD Thread,
                       IN HANDLE KeyHandle,
                       IN PCSTR ValueName,
                       IN ULONG TitleIndex,
                       IN ULONG Type,
                       IN PVOID InputBuffer,
                       IN ULONG DataSize)
{
    /* On client side we will marshal the REG_SZ and REG_MULTI_SZ and
     * supply a non-zero DataSize to the server. */
    DbgTrace("Setting value %s of key handle %p\n", ValueName, KeyHandle);
    if (DataSize == 0) {
	DbgTrace("Invalid data size (data size cannot be zero).\n");
	return STATUS_INVALID_PARAMETER;
    }
    if ((Type == REG_DWORD || Type == REG_DWORD_BIG_ENDIAN) &&
	(DataSize != sizeof(ULONG))) {
	DbgTrace("Expected data size 0x%zx got data size 0x%x.\n",
		 sizeof(ULONG), DataSize);
	return STATUS_INVALID_PARAMETER;
    }
    if (Type == REG_QWORD && DataSize != sizeof(ULONGLONG)) {
	DbgTrace("Expected data size 0x%zx got data size 0x%x.\n",
		 sizeof(ULONGLONG), DataSize);
	return STATUS_INVALID_PARAMETER;
    }
    assert(Thread->Process != NULL);
    PCM_KEY_OBJECT Key = NULL;
    RET_ERR(ObReferenceObjectByHandle(Thread->Process, KeyHandle,
				      OBJECT_TYPE_KEY, (POBJECT *)&Key));
    assert(Key != NULL);
    PVOID Data = NULL;
    RET_ERR_EX(MmMapUserBufferRO(&Thread->Process->VSpace,
				 (MWORD)InputBuffer, DataSize, &Data),
	       ObDereferenceObject(Key));
    assert(Data != NULL);
    RET_ERR_EX(CmpSetValueKey(Key, ValueName, Type, Data, DataSize),
	       {
		   ObDereferenceObject(Key);
		   MmUnmapUserBuffer(Data);
	       });
    ObDereferenceObject(Key);
    MmUnmapUserBuffer(Data);
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
