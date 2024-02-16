#include <nt.h>
#include "ex.h"

static inline PCSTR RtlDuplicateString(IN PCSTR String,
				       IN ULONG Tag)
{
    if (String == NULL) {
	return String;
    }

    SIZE_T BufLen = strlen(String) + 1;
    PCHAR Buf = ExAllocatePoolWithTag(BufLen, Tag);
    if (Buf == NULL) {
	return NULL;
    }
    memcpy(Buf, String, BufLen);
    return Buf;
}

static inline PCSTR RtlDuplicateStringEx(IN PCSTR String,
					 IN ULONG Length, /* Excluding trailing '\0' */
					 IN ULONG Tag)
{
    if (String == NULL) {
	return String;
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
