#include <ntdll.h>

static inline PVOID CmpAllocateHeap(ULONG Bytes)
{
    return RtlAllocateHeap(RtlGetProcessHeap(), 0, Bytes);
}

static inline VOID CmpFreeHeap(PVOID Mem)
{
    RtlFreeHeap(RtlGetProcessHeap(), 0, Mem);
}

static inline BOOLEAN CmpCheckSimpleTypes(IN ULONG Type,
					  IN ULONG DataSize)
{
    switch (Type) {
    case REG_DWORD:
    case REG_DWORD_BIG_ENDIAN:
	return DataSize == sizeof(ULONG);
	break;
    case REG_QWORD:
	return DataSize == sizeof(ULONGLONG);
	break;
    }
    return TRUE;
}

/*
 * Marshal the string data from UTF-16LE to UTF-8
 *
 * For string types, the client-side stub function NtSetValueKey accepts
 * UTF-16LE encoded strings to match Windows behavior while the system
 * service CmSetValueKey always expects NUL-terminated UTF-8 strings
 * (like all system services do). CmpMarshalRegData converts UTF-16 strings
 * into UTF-8 before NtSetValueKey calls server. For REG_MULTI_SZ, the user
 * supplies a string array that is terminated by an empty string ("\0").
 * This is not changed. The data size returned is the size of the entire
 * data buffer, including all the NUL characters.
 *
 * In the case of REG_SZ, REG_EXPAND_SZ and REG_MULTI_SZ, the user usually
 * specifies a zero DataSize. Therefore in these cases the input DataSize
 * is ignored. The output is the actual buffer size (including NUL).
 *
 * For REG_LINK, the user is required to specify a non-zero DataSize,
 * which is the size (in terms of CHAR, not WCHAR) of the string buffer,
 * EXCLUDING the terminating NUL. In this case we reject a zero DataSize,
 * and return the buffer size (including the terminating NUL) of the
 * NUL-terminated UTF-8 string.
 *
 * For all other types, nothing is done, except we assert when the
 * DataSize looks wrong.
 */
static NTSTATUS CmpMarshalRegData(IN ULONG Type,
				  IN OUT PVOID *Data,
				  IN OUT ULONG *DataSize)
{
    if (!CmpCheckSimpleTypes(Type, *DataSize)) {
	return STATUS_INVALID_PARAMETER;
    }
    if (*Data == NULL) {
	return STATUS_INVALID_PARAMETER;
    }
    if (Type == REG_LINK && *DataSize == 0) {
	return STATUS_INVALID_PARAMETER;
    }
    if (Type == REG_MULTI_SZ) {
	ULONG BufferSize = 0;
	for (PWSTR Ptr = (PWSTR)*Data; *Ptr != L'\0';) {
	    ULONG WcharCount = wcslen(Ptr);
	    /* For every WCHAR we need 3 CHARs plus the trailing NUL */
	    BufferSize += WcharCount + WcharCount / 2 + 1;
	    /* Skip the string plus the trailing wide char NUL */
	    Ptr += WcharCount + 1;
	}
	/* One more CHAR for the terminating empty string */
	BufferSize++;
	PCHAR Buffer = CmpAllocateHeap(BufferSize);
	if (Buffer == NULL) {
	    return STATUS_NO_MEMORY;
	}
	ULONG TotalDataSize = 0;
	PCHAR Dest = Buffer;
	for (PWSTR Ptr = (PWSTR)*Data; *Ptr != L'\0';) {
	    ULONG WcharCount = wcslen(Ptr);
	    ULONG BytesWritten = 0;
	    if (TotalDataSize >= BufferSize) {
		/* This shouldn't happen. Increase BufferSize when it does. */
		assert(FALSE);
		CmpFreeHeap(Buffer);
		return STATUS_NO_MEMORY;
	    }
	    RET_ERR_EX(RtlUnicodeToUTF8N(Dest, BufferSize-TotalDataSize,
					 &BytesWritten, Ptr, 2 * WcharCount),
		       CmpFreeHeap(Buffer));
	    Dest[BytesWritten] = '\0';
	    TotalDataSize += BytesWritten + 1;
	    Ptr += WcharCount + 1;
	}
	Dest[TotalDataSize++] = '\0';
	*Data = Buffer;
	*DataSize = TotalDataSize;
	return STATUS_SUCCESS;
    }
    if (Type == REG_SZ || Type == REG_EXPAND_SZ) {
	*DataSize = 2 * wcslen(*Data);
    }
    if (Type == REG_SZ || Type == REG_EXPAND_SZ || Type == REG_LINK) {
	/* For every WCHAR we need 3 CHARs for UTF-8, plus the trailing NUL */
	ULONG BufferSize = *DataSize + *DataSize / 2 + 1;
	PCHAR Buffer = CmpAllocateHeap(BufferSize);
	if (Buffer == NULL) {
	    return STATUS_NO_MEMORY;
	}
	RET_ERR_EX(RtlUnicodeToUTF8N(Buffer, BufferSize-1, DataSize,
				     *Data, *DataSize),
		   CmpFreeHeap(Buffer));
	Buffer[*DataSize] = '\0';
	(*DataSize)++;
	*Data = Buffer;
    }
    return STATUS_SUCCESS;
}

/*
 * Free the registry data buffer that was allocated by CmpMarshalRegData
 */
static VOID CmpFreeMarshaledRegData(IN ULONG Type,
				    IN PVOID Buffer)
{
    if (Type == REG_SZ || Type == REG_EXPAND_SZ || Type == REG_LINK ||
	Type == REG_MULTI_SZ) {
	CmpFreeHeap(Buffer);
    }
}

/*
 * Get the actual data size of string data.
 *
 * For REG_LINK, REG_SZ, REG_EXPAND_SZ and REG_MULTI_SZ, the DataSize is
 * ignored and the actual size of the buffer (including terminating NUL,
 * which for REG_MULTI_SZ there are two) is returned.
 *
 * For all other types, DataSize is returned unless when the DataSize
 * seems wrong, in which case we return 0;
 *
 * For REG_MULTI_SZ the data buffer is expected to be a string array of
 * NUL-terminated strings terminated by an empty string, ie.
 * String1\0String2\0String3\0\0
 */
static ULONG CmpGetSanitizedDataSize(IN ULONG Type,
				     IN PVOID Data,
				     IN ULONG DataSize)
{
    if (Data == NULL) {
	return 0;
    }
    if (Type == REG_SZ || Type == REG_EXPAND_SZ || Type == REG_LINK) {
	DataSize = strlen(Data) + 1;
    } else if (Type == REG_MULTI_SZ) {
	DataSize = 0;
	for (PCSTR Ptr = (PCSTR)Data; *Ptr != '\0';) {
	    ULONG NumBytes = strlen(Ptr) + 1;
	    DataSize += NumBytes;
	    Ptr += NumBytes;
	}
	DataSize++;
    } else {
	if (!CmpCheckSimpleTypes(Type, DataSize)) {
	    return 0;
	}
    }
    return DataSize;
}

NTAPI NTSTATUS NtSetValueKey(IN HANDLE KeyHandle,
                             IN PUNICODE_STRING ValueName,
                             IN ULONG TitleIndex,
                             IN ULONG Type,
                             IN PVOID Data,
                             IN ULONG DataSize)
{
    RET_ERR(CmpMarshalRegData(Type, &Data, &DataSize));
    RET_ERR_EX(CmSetValueKey(KeyHandle, ValueName, TitleIndex,
			     Type, Data, DataSize),
	       CmpFreeMarshaledRegData(Type, Data));
    CmpFreeMarshaledRegData(Type, Data);
    return STATUS_SUCCESS;
}

/*
 * UTF-8 version of NtSetValueKey, where ValueName and the registry
 * data (ie. REG_SZ, REG_MULTI_SZ, and REG_LINK) are NUL-terminated
 * UTF-8 strings.
 *
 * For REG_SZ, REG_MULTI_SZ, and REG_LINK, the data size is ignored.
 * The user will typically set it to zero.
 *
 * For all other data types, the data size cannot be zero.
 */
NTAPI NTSTATUS NtSetValueKeyA(IN HANDLE KeyHandle,
                              IN PCSTR ValueName,
                              IN ULONG TitleIndex,
                              IN ULONG Type,
                              IN PVOID Data,
                              IN ULONG DataSize)
{
    DataSize = CmpGetSanitizedDataSize(Type, Data, DataSize);
    if (DataSize == 0) {
	return STATUS_INVALID_PARAMETER;
    }
    RET_ERR(CmSetValueKeyA(KeyHandle, ValueName, TitleIndex,
			   Type, Data, DataSize));
    return STATUS_SUCCESS;
}
