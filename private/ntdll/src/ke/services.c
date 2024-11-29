/*
 * A note about UTF-8 vs UTF-16, in particular, how we deal with string types
 * in the registry:
 *
 * The native encoding of Windows is UTF-16LE (LE stands for little-endian).
 * This is a relic of history and in today's hindsight a bad idea. A common
 * misconception is that UTF-16 is a fixed-length encoding, and therefore
 * choosing UTF-16 over UTF-8 would simplify many string operations, such as
 * computing the string lengths. THIS IS PATENTLY FALSE! UTF-16 is in fact a
 * variable-length encoding just like UTF-8. The full representation of the
 * entire Unicode codespace in UTF-16 requires four-bytes, just like UTF-8
 * or UTF-32.
 *
 * So where does this common misconception come from? The reason is that for
 * a long time, what would become today's UTF-16 was a now-obsolete standard
 * called UCS-2, which is indeed a fixed-length encoding, but it only covers
 * the so-called Basic Multilingual Plane (BMP) of today's Unicode standard.
 * UTF-16 is an extension to UCS-2, so a program written with the assumption
 * of UCS-2 in mind would function as intended, as long as it never has to
 * process codepoints outside the Basic Multilingual Plane. Since the BMP
 * includes the vast majority of the scripts and characters used in today's
 * world (in particular, it includes the CJK Unified Ideographs, which is
 * the whole reason that a wide-character scheme is needed to begin with),
 * assuming fixed-length encoding for UTF-16 would produce hard-to-test
 * problems that only trigger when the user supplies a character that lies
 * outside the BMP.
 *
 * However, full UTF-16 did not come into fruition well after the first
 * release of Windows NT 3.1 (in fact UTF-16 wasn't even ready by the time
 * that Windows NT 3.51 shipped). By the time that the full UTF-16 standard
 * was available, the Windows NT development was way past the point where
 * switching from UTF-16 to UTF-8 is anything other than a highly non-trivial
 * task. Therefore the entire Windows ecosystem is stuck with a less-than-
 * ideal encoding scheme, which has neither the backwards compatibility of
 * UTF-8, nor the programming benefit of a fixed-encoding scheme.
 *
 * Since we are re-implementing NT on seL4, now is a great time to actually
 * fix this issue. On Neptune OS, the native encoding is always UTF-8. The
 * Neptune OS Executive always stores its internal string data in UTF-8
 * encoding. When string data cross the process boundary between NT clients
 * and the Executive process, we perform the necessary conversions between
 * UTF-8 and UTF-16, the details of which are described as follows:
 *
 * Whenever a system service deals with string data, such as paths or registry
 * string values, the Neptune OS Native API provides two sets of API calls:
 * one handles UTF-16 wide character strings, and the other handles UTF-8
 * encoded single-byte strings. The UTF-16 version has the same stub routine
 * name as the equivalent Windows system service, and the UTF-8 version adds
 * an "A" to the end of the stub routine name. For instance, for the system
 * service NtDisplayString, we provide both the following:
 *
 *    NTSTATUS NtDisplayString(IN PUNICODE_STRING Utf16String);
 *
 * and
 *
 *    NTSTATUS NtDisplayStringA(IN PCSTR Utf8String);
 *
 * Here the "A" version accepts a NUL-terminated UTF-8 encoded single-byte
 * string, and the non-"A" version accepts a pointer to the wide-character
 * UNICODE_STRING (the wide-character string is not required to be NUL-
 * terminated). When the user calls the UTF-16 version, the stub routine
 * automatically converts the UTF-16 string into UTF-8, and passes it to
 * the "A" version. Therefore the "A" version of the system service is in
 * fact the native version and does not incur a performance loss from the
 * string conversions. New programs should ideally target the UTF-8 version.
 *
 * Similarly, for registry data, NtSetValueKey will accept UTF-16 encoded
 * wide-character strings for REG_SZ, REG_EXPAND_SZ, and REG_MULTI_SZ,
 * while NtSetValueKeyA accepts NUL-terminated UTF-8 strings. The UTF-16
 * version converts UTF-16 into UTF-8 and calls the native UTF-8 service.
 * New programs should ideally use the UTF-8 version.
 *
 * The UTF-16 to UTF-8 conversion described above happens on the client
 * side (ie. by the stub routine in ntdll). This is always the case when
 * the client sends string data to the NTOS server (ie. by providing a
 * path or an input buffer with registry string data). If on the other
 * hand, the server sends string data to the client (ie. server writes
 * into an output buffer provided by the client, in say NtQueryValueKey),
 * the conversion happens on the server-side: the server converts its
 * internal UTF-8 strings into UTF-16 strings and writes them into the
 * client buffer.
 *
 * In both cases, the non-"A" version handles UTF-16 string data (both
 * input and output), and the "A" version handles UTF-8 strings (again,
 * both in input buffers and output buffers). A system service routine
 * never mixes UTF-8 and UTF-16. For instance, for
 *
 *     NTSTATUS NtQueryValueKey(IN HANDLE KeyHandle,
 *				IN PUNICODE_STRING ValueName,
 *				IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
 *				IN PVOID KeyValueInformation,
 *				IN ULONG Length,
 *				OUT PULONG ResultLength);
 *
 * both ValueName and KeyValueInformation are UTF-16 encoded strings
 * (KeyValueInformation contains a Name member which is UTF-16), while for
 *
 *     NTSTATUS NtQueryValueKeyA(IN HANDLE KeyHandle,
 *				 IN PCSTR ValueName,
 *				 IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
 *				 IN PVOID KeyValueInformation,
 *				 IN ULONG Length,
 *				 OUT PULONG ResultLength);
 *
 * both ValueName and KeyValueInformation are UTF-8 encoded strings
 * (KeyValueInformation contains a Name member which is UTF-8). If you look
 * at the ntos code you will see a function called NtQueryValueKeyW, which
 * takes UTF-8 ValueName and writes UTF-16 KeyValueInformation, but this is
 * a purely internal function that only exist on the server. You cannot call
 # it from client side. All of the client-side stub routines have consistent
 * encodings. The "W"-functions exist because for output strings we perform
 * the conversion on server side so server needs to provide two versions of
 * the same system service, one for UTF-8, and one for UTF-16.
 */

#include <ntdll.h>
#include <client_svc_helpers.h>

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

static inline BOOLEAN CmpIsStringType(IN ULONG Type)
{
    return Type == REG_SZ || Type == REG_EXPAND_SZ ||
	Type == REG_LINK || Type == REG_MULTI_SZ;
}

#define MAX_MSG_BUF_OFFSET	(IPC_BUFFER_COMMIT - 128)

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
static NTSTATUS CmpMarshalRegData(IN PVOID Data,
				  IN ULONG DataSize,
				  IN ULONG Type,
				  OUT SERVICE_ARGUMENT *DataArg,
				  OUT SERVICE_ARGUMENT *DataSizeArg,
				  OUT SERVICE_ARGUMENT *DataTypeArg,
				  IN BOOLEAN InParam,
				  OUT ULONG *MsgBufOffset)
{
    assert(MsgBufOffset != NULL);
    assert(*MsgBufOffset < SVC_MSGBUF_SIZE);
    if (*MsgBufOffset >= SVC_MSGBUF_SIZE) {
	return STATUS_INTERNAL_ERROR;
    }
    if (Data == NULL) {
	return STATUS_INVALID_PARAMETER;
    }
    if (KiPtrInSvcMsgBuf(Data)) {
	return STATUS_INVALID_USER_BUFFER;
    }
    if (!CmpCheckSimpleTypes(Type, DataSize)) {
	return STATUS_INVALID_PARAMETER;
    }
    if (Type == REG_LINK && DataSize == 0) {
	return STATUS_INVALID_PARAMETER;
    }
    /* For string types, compute the data size. */
    if (Type == REG_MULTI_SZ) {
	DataSize = 0;
	for (PWSTR Ptr = (PWSTR)Data; *Ptr != L'\0';) {
	    ULONG WcharCount = wcslen(Ptr) + 1;
	    DataSize += sizeof(WCHAR) * WcharCount;
	    /* Skip the string plus the trailing wide char NUL */
	    Ptr += WcharCount;
	}
	/* One more WCHAR for the terminating empty string */
	DataSize += sizeof(WCHAR);
    } else if (Type == REG_SZ || Type == REG_EXPAND_SZ) {
	DataSize = sizeof(WCHAR) * (wcslen(Data) + 1);
    }
    if (DataSize == 0) {
	return STATUS_INVALID_PARAMETER;
    }
    PVOID Buffer = Data;
    ULONG MarshaledDataSize = 0;
    if (CmpIsStringType(Type)) {
	/* For string types compute the UTF-8 string size */
	ULONG BufferSize = 0;
	RET_ERR(RtlUnicodeToUTF8N(NULL, 0, &BufferSize, Data, DataSize));
	/* We leave a little bit of space after the registry data so parameters
	 * following the registry data can be marshaled successfully. If the data
	 * fits in the message buffer, then marshal them there. Otherwise allocate
	 * a buffer from the process heap. */
	if (*MsgBufOffset + BufferSize < MAX_MSG_BUF_OFFSET) {
	    Buffer = &OFFSET_TO_ARG(*MsgBufOffset, CHAR);
	    MarshaledDataSize = BufferSize;
	} else {
	    Buffer = CmpAllocateHeap(BufferSize);
	    if (Buffer == NULL) {
		return STATUS_NO_MEMORY;
	    }
	}
	RET_ERR_EX(RtlUnicodeToUTF8N(Buffer, BufferSize, &BufferSize,
				     Data, DataSize),
		   CmpFreeHeap(Buffer));
	DataSize = BufferSize;
    } else if (*MsgBufOffset + DataSize < MAX_MSG_BUF_OFFSET) {
	Buffer = &OFFSET_TO_ARG(*MsgBufOffset, CHAR);
	memcpy(Buffer, Data, DataSize);
	MarshaledDataSize = DataSize;
    }
    DataArg->Word = (MWORD)Buffer;
    DataSizeArg->Word = DataSize;
    DataTypeArg->Word = Type;
    *MsgBufOffset += MarshaledDataSize;
    return STATUS_SUCCESS;
}

/*
 * Free the registry data buffer that was allocated by CmpMarshalRegData
 */
static VOID CmpFreeMarshaledRegData(IN PVOID Data,
				    IN SERVICE_ARGUMENT DataArg,
				    IN SERVICE_ARGUMENT DataSizeArg,
				    IN SERVICE_ARGUMENT DataTypeArg)
{
    if (CmpIsStringType(DataTypeArg.Word) && !KiPtrInSvcMsgBuf((PVOID)DataArg.Word)) {
	CmpFreeHeap((PVOID)DataArg.Word);
    }
}

/*
 * Get the actual data size of UTF-8 string data.
 *
 * For REG_LINK, REG_SZ, REG_EXPAND_SZ and REG_MULTI_SZ, the DataSize is
 * ignored and the actual size of the buffer (including terminating NUL,
 * and for REG_MULTI_SZ this includes the empty string {'\0'}) is returned.
 *
 * For all other types, DataSize is returned unless when the DataSize
 * seems wrong, in which case we return error;
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
    } else if (!CmpCheckSimpleTypes(Type, DataSize)) {
	return 0;
    }
    return DataSize;
}

/*
 * UTF-8 version of CmpMarshalRegData, where the registry string
 * data (ie. REG_SZ, REG_MULTI_SZ, REG_LINK, REG_EXPAND_SZ) are
 * NUL-terminated UTF-8 strings.
 *
 * For REG_SZ, REG_MULTI_SZ, and REG_LINK, the data size is ignored.
 * The user will typically set it to zero.
 *
 * For all other data types, the data size cannot be zero.
 */
static NTSTATUS CmpMarshalRegDataA(IN PVOID Data,
				   IN ULONG DataSize,
				   IN ULONG Type,
				   OUT SERVICE_ARGUMENT *DataArg,
				   OUT SERVICE_ARGUMENT *DataSizeArg,
				   OUT SERVICE_ARGUMENT *DataTypeArg,
				   IN BOOLEAN InParam,
				   OUT ULONG *MsgBufOffset)
{
    assert(MsgBufOffset != NULL);
    assert(*MsgBufOffset < SVC_MSGBUF_SIZE);
    if (*MsgBufOffset >= SVC_MSGBUF_SIZE) {
	return STATUS_INTERNAL_ERROR;
    }
    if (Data == NULL) {
	return STATUS_INVALID_PARAMETER;
    }
    if (KiPtrInSvcMsgBuf(Data)) {
	return STATUS_INVALID_USER_BUFFER;
    }
    /* For string types, compute the data size. */
    DataSize = CmpGetSanitizedDataSize(Type, Data, DataSize);
    if (!DataSize) {
	return STATUS_INVALID_PARAMETER;
    }
    /* If the data fit in the service message buffer, copy them there. */
    PVOID Buffer = Data;
    ULONG MarshaledDataSize = 0;
    if (*MsgBufOffset + DataSize < MAX_MSG_BUF_OFFSET) {
	Buffer = &OFFSET_TO_ARG(*MsgBufOffset, CHAR);
	memcpy(Buffer, Data, DataSize);
	MarshaledDataSize = DataSize;
    }
    DataArg->Word = (MWORD)Buffer;
    DataSizeArg->Word = DataSize;
    DataTypeArg->Word = Type;
    *MsgBufOffset += MarshaledDataSize;
    return STATUS_SUCCESS;
}

static inline NTSTATUS CmpMarshalKeyValueInfoBuffer(IN OPTIONAL PVOID ClientBuffer,
						    IN ULONG BufferSize,
						    IN KEY_VALUE_INFORMATION_CLASS InfoClass,
						    OUT SERVICE_ARGUMENT *BufferArg,
						    OUT SERVICE_ARGUMENT *SizeArg,
						    OUT SERVICE_ARGUMENT *TypeArg,
						    IN BOOLEAN Copy,
						    OUT ULONG *MsgBufOffset)
{
    if ((InfoClass == KeyValueFullInformationAlign64 ||
	 InfoClass == KeyValuePartialInformationAlign64)
	&& (ALIGN_DOWN_POINTER(ClientBuffer, ULONGLONG) != ClientBuffer)) {
	return STATUS_DATATYPE_MISALIGNMENT;
    }
    TypeArg->Word = InfoClass;
    RET_ERR(KiServiceMarshalBuffer(ClientBuffer, BufferSize, BufferArg,
				   SizeArg, Copy, MsgBufOffset));
    return STATUS_SUCCESS;
}

#include <ntdll_syssvc_gen.c>
