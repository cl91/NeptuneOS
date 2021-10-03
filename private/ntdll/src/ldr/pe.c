/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            lib/rtl/image.c
 * PURPOSE:         Image handling functions
 *                  Relocate functions were previously located in
 *                  ntoskrnl/ldr/loader.c and
 *                  dll/ntdll/ldr/utils.c files
 * PROGRAMMER:      Eric Kohl + original authors from loader.c and utils.c file
 *                  Aleksey Bragin
 */

/* INCLUDES *****************************************************************/

#include "ldrp.h"

/* FUNCTIONS *****************************************************************/

/*
 * @implemented
 * @note: This is the version of RtlpImageNtHeaderEx guarded by SEH.
 */
NTSTATUS NTAPI RtlImageNtHeaderEx(IN ULONG Flags,
				  IN PVOID Base,
				  IN ULONG64 Size,
				  OUT PIMAGE_NT_HEADERS *OutHeaders)
{
    NTSTATUS Status;

    _SEH2_TRY {
	/* Assume failure. This is also done in RtlpImageNtHeaderEx,
	 * but this is guarded by SEH. */
	if (OutHeaders != NULL) {
	    *OutHeaders = NULL;
	}
        Status = RtlpImageNtHeaderEx(Flags, Base, Size, OutHeaders);
    } _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
        /* Fail with the SEH error */
        Status = _SEH2_GetExceptionCode();
    }

    return Status;
}

/*
 * @implemented
 */
PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(IN PVOID Base)
{
    PIMAGE_NT_HEADERS NtHeader;

    /* Call the new API */
    RtlImageNtHeaderEx(RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK,
                       Base, 0, &NtHeader);
    return NtHeader;
}

static PIMAGE_BASE_RELOCATION
LdrpProcessRelocationBlockLongLong(IN ULONG_PTR Address,
				   IN ULONG Count,
				   IN PUSHORT TypeOffset,
				   IN LONGLONG Delta)
{
    SHORT Offset;
    USHORT Type;
    ULONG i;
    PUSHORT ShortPtr;
    PULONG LongPtr;
    PULONGLONG LongLongPtr;

    for (i = 0; i < Count; i++) {
        Offset = SWAPW(*TypeOffset) & 0xFFF;
        Type = SWAPW(*TypeOffset) >> 12;
        ShortPtr = (PUSHORT)(RVA(Address, Offset));
        /*
        * Don't relocate within the relocation section itself.
        * GCC/LD sometimes generates relocation records for the relocation section.
        * This is a bug in GCC/LD.
        * Fix for it disabled, since it was only in ntoskrnl and not in ntdll
        */
        /*
        if ((ULONG_PTR)ShortPtr < (ULONG_PTR)RelocationDir ||
        (ULONG_PTR)ShortPtr >= (ULONG_PTR)RelocationEnd)
        {*/
        switch (Type) {
            /* case IMAGE_REL_BASED_SECTION : */
            /* case IMAGE_REL_BASED_REL32 : */
        case IMAGE_REL_BASED_ABSOLUTE:
            break;

        case IMAGE_REL_BASED_HIGH:
            *ShortPtr = HIWORD(MAKELONG(0, *ShortPtr) + (Delta & 0xFFFFFFFF));
            break;

        case IMAGE_REL_BASED_LOW:
            *ShortPtr = SWAPW(*ShortPtr) + LOWORD(Delta & 0xFFFF);
            break;

        case IMAGE_REL_BASED_HIGHLOW:
            LongPtr = (PULONG)RVA(Address, Offset);
            *LongPtr = SWAPD(*LongPtr) + (Delta & 0xFFFFFFFF);
            break;

        case IMAGE_REL_BASED_DIR64:
            LongLongPtr = (PUINT64)RVA(Address, Offset);
            *LongLongPtr = SWAPQ(*LongLongPtr) + Delta;
            break;

        case IMAGE_REL_BASED_HIGHADJ:
        case IMAGE_REL_BASED_MIPS_JMPADDR:
        default:
            DPRINT1("Unknown/unsupported fixup type %hu.\n", Type);
            DPRINT1("Address %p, Current %u, Count %u, *TypeOffset %x\n",
                    (PVOID)Address, i, Count, SWAPW(*TypeOffset));
            return (PIMAGE_BASE_RELOCATION)NULL;
        }

        TypeOffset++;
    }

    return (PIMAGE_BASE_RELOCATION)TypeOffset;
}

ULONG LdrpRelocateImage(IN PVOID BaseAddress,
			IN PCCH LoaderName,
			IN ULONG Success,
			IN ULONG Conflict,
			IN ULONG Invalid)
{
    return LdrpRelocateImageWithBias(BaseAddress, 0, LoaderName,
				     Success, Conflict, Invalid);
}

ULONG LdrpRelocateImageWithBias(IN PVOID BaseAddress,
				IN LONGLONG AdditionalBias,
				IN PCCH LoaderName,
				IN ULONG Success,
				IN ULONG Conflict,
				IN ULONG Invalid)
{
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_DATA_DIRECTORY RelocationDDir;
    PIMAGE_BASE_RELOCATION RelocationDir, RelocationEnd;
    ULONG Count;
    ULONG_PTR Address;
    PUSHORT TypeOffset;
    LONGLONG Delta;

    NtHeaders = RtlImageNtHeader(BaseAddress);

    if (NtHeaders == NULL)
        return Invalid;

    if (SWAPW(NtHeaders->FileHeader.Characteristics) & IMAGE_FILE_RELOCS_STRIPPED) {
        return Conflict;
    }

    RelocationDDir = &NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (SWAPD(RelocationDDir->VirtualAddress) == 0 || SWAPD(RelocationDDir->Size) == 0) {
        return Success;
    }

    Delta = (ULONG_PTR)BaseAddress - SWAPD(NtHeaders->OptionalHeader.ImageBase) + AdditionalBias;
    RelocationDir = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)BaseAddress + SWAPD(RelocationDDir->VirtualAddress));
    RelocationEnd = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)RelocationDir + SWAPD(RelocationDDir->Size));

    while (RelocationDir < RelocationEnd && SWAPW(RelocationDir->SizeOfBlock) > 0) {
        Count = (SWAPW(RelocationDir->SizeOfBlock) - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
        Address = (ULONG_PTR)RVA(BaseAddress, SWAPD(RelocationDir->VirtualAddress));
        TypeOffset = (PUSHORT)(RelocationDir + 1);

        RelocationDir = LdrpProcessRelocationBlockLongLong(Address,
                        Count,
                        TypeOffset,
                        Delta);

        if (RelocationDir == NULL) {
            DPRINT1("Error during call to LdrpProcessRelocationBlockLongLong()!\n");
            return Invalid;
        }
    }

    return Success;
}
