#include <nt.h>
#include "ex.h"

static inline PCHAR RtlDuplicateString(IN PCSTR String,
				       IN ULONG Tag)
{
    if (String == NULL) {
	return NULL;
    }

    SIZE_T BufLen = strlen(String) + 1;
    PCHAR Buf = ExAllocatePoolWithTag(BufLen, Tag);
    if (Buf == NULL) {
	return NULL;
    }
    memcpy(Buf, String, BufLen);
    return Buf;
}

static inline PCHAR RtlDuplicateStringEx(IN PCSTR String,
					 IN ULONG Length, /* Excluding trailing '\0' */
					 IN ULONG Tag)
{
    if (String == NULL) {
	return NULL;
    }

    PCHAR Buf = ExAllocatePoolWithTag(Length+1, Tag);
    if (Buf == NULL) {
	return NULL;
    }
    ULONG Index;
    for (Index = 0; Index < Length; Index++) {
	if (String[Index] == '\0') {
	    break;
	}
	Buf[Index] = String[Index];
    }
    Buf[Index] = '\0';
    return Buf;
}

/*
 * Append the string to the end of the given buffer. The valid data length is
 * given by the DataLength parameter which will be updated to the new data length.
 * Note the date length does NOT include the trailing NUL, and this routine does
 * NOT write the trailing NUL to the string buffer.
 */
VOID RtlAppendStringBuffer(IN PCSTR String,
			   IN OUT ULONG *DataLength,
			   OUT PCHAR Buffer,
			   IN ULONG BufferLength)
{
    ULONG Length = strlen(String);
    if (*DataLength + Length <= BufferLength) {
	memcpy(Buffer + *DataLength, String, Length);
	*DataLength += Length;
    } else if (Length < BufferLength) {
	ULONG RemainingLength = BufferLength - Length;
	memmove(Buffer,
		Buffer + *DataLength - RemainingLength,
		RemainingLength);
	memcpy(Buffer + RemainingLength, String, Length);
	*DataLength = BufferLength;
    } else {
	/* In this case we truncate the head of the message. */
	memcpy(Buffer, String + Length - BufferLength,
	       BufferLength);
	*DataLength = BufferLength;
    }
}

static inline ULONG RtlNumberOfSetBits(ULONG Integer)
{
    return __builtin_popcount(Integer);
}

static inline ULONG RtlFirstSetBit(ULONG Integer)
{
    return __builtin_ffs(Integer);
}

/* pe.c */
NTSTATUS RtlImageNtHeaderEx(IN PIO_FILE_CONTROL_BLOCK Fcb,
			    OUT PIMAGE_NT_HEADERS *OutHeaders,
			    OUT ULONG64 *NtHeaderOffset);
ULONG64 RtlImageDirectoryEntryToFileOffset(IN PIO_FILE_OBJECT FileObject,
					   IN USHORT Directory,
					   OUT OPTIONAL ULONG *Size);
ULONG64 RtlImageRvaToFileOffset(IN PIO_FILE_OBJECT FileObject,
				IN ULONG Rva);

FORCEINLINE PIMAGE_NT_HEADERS RtlImageNtHeader(IN PIO_FILE_CONTROL_BLOCK Fcb)
{
    PIMAGE_NT_HEADERS NtHeader = NULL;
    ULONG64 NtHeaderOffset = 0;
    if (!NT_SUCCESS(RtlImageNtHeaderEx(Fcb, &NtHeader, &NtHeaderOffset))) {
	return NULL;
    }
    return NtHeader;
}
