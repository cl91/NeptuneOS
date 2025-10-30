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
#include <string.h>

/* FUNCTIONS *****************************************************************/

NTSTATUS RtlpImageNtHeaderEx(IN ULONG Flags,
			     IN PVOID Base,
			     IN ULONG64 Size,
			     OUT PIMAGE_NT_HEADERS *OutHeaders)
{
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_DOS_HEADER DosHeader;
    BOOLEAN WantsRangeCheck;
    ULONG NtHeaderOffset;

    /* You must want NT Headers, no? */
    if (OutHeaders == NULL) {
        DPRINT1("OutHeaders is NULL\n");
        return STATUS_INVALID_PARAMETER;
    }

    /* Assume failure */
    *OutHeaders = NULL;

    /* Validate Flags */
    if (Flags & ~RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK) {
        DPRINT1("Invalid flags: 0x%x\n", Flags);
        return STATUS_INVALID_PARAMETER;
    }

    /* Validate base */
    if ((Base == NULL) || (Base == (PVOID)-1)) {
        DPRINT1("Invalid base address: %p\n", Base);
        return STATUS_INVALID_PARAMETER;
    }

    /* Check if the caller wants range checks */
    WantsRangeCheck = !(Flags & RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK);
    if (WantsRangeCheck) {
        /* Make sure the image size is at least big enough for the DOS header */
        if (Size < sizeof(IMAGE_DOS_HEADER)) {
            DPRINT1("File buffer size too small\n");
            return STATUS_INVALID_IMAGE_FORMAT;
        }
    }

    /* Check if the DOS Signature matches */
    DosHeader = Base;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        /* Not a valid COFF */
        DPRINT1("Invalid image DOS signature (expected 0x%x found 0x%x)\n",
		IMAGE_DOS_SIGNATURE, DosHeader->e_magic);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if (DosHeader->e_lfanew <= 0) {
        DPRINT1("Not a Windows executable, e_lfanew is %d\n", DosHeader->e_lfanew);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    /* Get the offset to the NT headers (and copy from LONG to ULONG) */
    NtHeaderOffset = DosHeader->e_lfanew;

    /* The offset must not be larger than 256MB, as a hard-coded check.
       In Windows this check is only done in user mode, not in kernel mode,
       but it shouldn't harm to have it anyway. Note that without this check,
       other overflow checks would become necessary! */
    if (NtHeaderOffset >= (256 * 1024 * 1024)) {
        DPRINT1("NT headers offset is larger than 256MB!\n");
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    /* Check if the caller wants validation */
    if (WantsRangeCheck) {
        /* Make sure the file header fits into the size */
        if ((NtHeaderOffset + RTL_SIZEOF_THROUGH_FIELD(IMAGE_NT_HEADERS, FileHeader)) >= Size) {
            /* Fail */
            DPRINT1("NT headers beyond file buffer size!\n");
            return STATUS_INVALID_IMAGE_FORMAT;
        }
    }

    /* Now get a pointer to the NT Headers */
    NtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)Base + NtHeaderOffset);

    /* Verify the PE Signature */
    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        DPRINT1("Invalid image NT signature (expected 0x%x found 0x%x)\n",
		IMAGE_NT_SIGNATURE, NtHeaders->Signature);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    /* Now return success and the NT header */
    *OutHeaders = NtHeaders;
    return STATUS_SUCCESS;
}

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

    __try {
	/* Assume failure. This is also done in RtlpImageNtHeaderEx,
	 * but this is guarded by SEH. */
	if (OutHeaders) {
	    *OutHeaders = NULL;
	}
        Status = RtlpImageNtHeaderEx(Flags, Base, Size, OutHeaders);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
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

/*
 * @implemented
 */
PVOID NTAPI RtlImageDirectoryEntryToData(IN PVOID BaseAddress,
					 IN BOOLEAN MappedAsImage,
					 IN USHORT Directory,
					 IN PULONG Size)
{
    /* Magic flag for non-mapped images. */
    if ((ULONG_PTR)BaseAddress & 1) {
        BaseAddress = (PVOID)((ULONG_PTR)BaseAddress & ~1);
        MappedAsImage = FALSE;
    }

    PIMAGE_NT_HEADERS NtHeader = RtlImageNtHeader(BaseAddress);
    if (!NtHeader)
        return NULL;

    if (Directory >= NtHeader->OptionalHeader.NumberOfRvaAndSizes)
        return NULL;

    ULONG Va = NtHeader->OptionalHeader.DataDirectory[Directory].VirtualAddress;
    if (Va == 0)
        return NULL;

    *Size = NtHeader->OptionalHeader.DataDirectory[Directory].Size;

    if (MappedAsImage || Va < NtHeader->OptionalHeader.SizeOfHeaders)
        return (PVOID)((ULONG_PTR)BaseAddress + Va);

    /* Image mapped as ordinary file, we must find raw pointer */
    return RtlImageRvaToVa(NtHeader, BaseAddress, Va, NULL);
}

/*
 * @implemented
 */
PIMAGE_SECTION_HEADER NTAPI RtlImageRvaToSection(IN PIMAGE_NT_HEADERS NtHeader,
						 IN PVOID BaseAddress,
						 IN ULONG Rva)
{
    PIMAGE_SECTION_HEADER Section;
    ULONG Va;
    ULONG Count;

    Count = NtHeader->FileHeader.NumberOfSections;
    Section = IMAGE_FIRST_SECTION(NtHeader);

    while (Count--) {
        Va = Section->VirtualAddress;
        if ((Va <= Rva) && (Rva < Va + Section->SizeOfRawData)) {
            return Section;
	}
        Section++;
    }

    return NULL;
}

/*
 * @implemented
 */
PVOID NTAPI RtlImageRvaToVa(IN PIMAGE_NT_HEADERS NtHeader,
			    IN PVOID BaseAddress,
			    IN ULONG Rva,
			    IN PIMAGE_SECTION_HEADER *SectionHeader)
{
    PIMAGE_SECTION_HEADER Section = NULL;

    if (SectionHeader)
        Section = *SectionHeader;

    if ((Section == NULL) || (Rva < Section->VirtualAddress) ||
        (Rva >= Section->VirtualAddress + Section->SizeOfRawData)) {
        Section = RtlImageRvaToSection(NtHeader, BaseAddress, Rva);
        if (Section == NULL)
            return NULL;

        if (SectionHeader)
            *SectionHeader = Section;
    }

    return (PVOID)((ULONG_PTR)BaseAddress + Rva + (ULONG_PTR)Section->PointerToRawData -
                   (ULONG_PTR)Section->VirtualAddress);
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
        Offset = *TypeOffset & 0xFFF;
        Type = *TypeOffset >> 12;
        ShortPtr = (PUSHORT)(RVA(Address, Offset));
        switch (Type) {
        case IMAGE_REL_BASED_ABSOLUTE:
            break;

        case IMAGE_REL_BASED_HIGH:
            *ShortPtr = HIWORD(MAKELONG(0, *ShortPtr) + (Delta & 0xFFFFFFFF));
            break;

        case IMAGE_REL_BASED_LOW:
            *ShortPtr = *ShortPtr + LOWORD(Delta & 0xFFFF);
            break;

        case IMAGE_REL_BASED_HIGHLOW:
            LongPtr = (PULONG)RVA(Address, Offset);
            *LongPtr = *LongPtr + (Delta & 0xFFFFFFFF);
            break;

        case IMAGE_REL_BASED_DIR64:
            LongLongPtr = (PUINT64)RVA(Address, Offset);
            *LongLongPtr = *LongLongPtr + Delta;
            break;

        case IMAGE_REL_BASED_HIGHADJ:
        case IMAGE_REL_BASED_MIPS_JMPADDR:
        /* case IMAGE_REL_BASED_SECTION : */
        /* case IMAGE_REL_BASED_REL32 : */
        default:
            DPRINT1("Unknown/unsupported fixup type %hu.\n", Type);
            DPRINT1("Address %p, Current %u, Count %u, *TypeOffset %x\n",
                    (PVOID)Address, i, Count, *TypeOffset);
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
    PIMAGE_NT_HEADERS NtHeaders = RtlImageNtHeader(BaseAddress);

    if (!NtHeaders)
        return Invalid;

    if (NtHeaders->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) {
        return Conflict;
    }

    PIMAGE_DATA_DIRECTORY RelocationDDir =
	&NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (!RelocationDDir->VirtualAddress || !RelocationDDir->Size) {
        return Success;
    }

    LONGLONG Delta = (ULONG_PTR)BaseAddress -
	NtHeaders->OptionalHeader.ImageBase + AdditionalBias;
    PIMAGE_BASE_RELOCATION RelocationDir = (PIMAGE_BASE_RELOCATION)(
	(ULONG_PTR)BaseAddress + RelocationDDir->VirtualAddress);
    PIMAGE_BASE_RELOCATION RelocationEnd = (PIMAGE_BASE_RELOCATION)(
	(ULONG_PTR)RelocationDir + RelocationDDir->Size);

    while (RelocationDir < RelocationEnd && RelocationDir->SizeOfBlock > 0) {
	ULONG Count = (RelocationDir->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))
	    / sizeof(USHORT);
	ULONG_PTR Address = (ULONG_PTR)RVA(BaseAddress, RelocationDir->VirtualAddress);
	PUSHORT TypeOffset = (PUSHORT)(RelocationDir + 1);

        RelocationDir = LdrpProcessRelocationBlockLongLong(Address,
							   Count,
							   TypeOffset,
							   Delta);

        if (!RelocationDir) {
            DPRINT1("Error during call to LdrpProcessRelocationBlockLongLong()!\n");
            return Invalid;
        }
    }

    return Success;
}

PVOID LdrpFetchAddressOfEntryPoint(IN PVOID ImageBase)
{
    PIMAGE_NT_HEADERS NtHeaders = RtlImageNtHeader(ImageBase);
    if (!NtHeaders) {
	return NULL;
    }

    ULONG_PTR EntryPoint = NtHeaders->OptionalHeader.AddressOfEntryPoint;
    if (EntryPoint) {
	EntryPoint += (ULONG_PTR)ImageBase;
    }

    return (PVOID)EntryPoint;
}

static USHORT LdrpNameToOrdinal(IN PCSTR ImportName,
				IN ULONG NumberOfNames,
				IN PVOID ExportBase,
				IN PULONG NameTable,
				IN PUSHORT OrdinalTable)
{
    LONG Start, End, Next, CmpResult;

    /* Use classical binary search to find the ordinal */
    Start = Next = 0;
    End = NumberOfNames - 1;
    while (End >= Start) {
	/* Next will be exactly between Start and End */
	Next = (Start + End) >> 1;

	/* Compare this name with the one we need to find */
	CmpResult = strcmp(ImportName, (PCHAR)((ULONG_PTR) ExportBase + NameTable[Next]));

	/* We found our entry if result is 0 */
	if (!CmpResult)
	    break;

	/* We didn't find, update our range then */
	if (CmpResult < 0) {
	    End = Next - 1;
	} else if (CmpResult > 0) {
	    Start = Next + 1;
	}
    }

    /* If end is before start, then the search failed */
    if (End < Start)
	return -1;

    /* Return found name */
    return OrdinalTable[Next];
}

static NTSTATUS LdrpSnapThunk(IN PVOID ExportBase,
			      IN PVOID ImportBase,
			      IN PIMAGE_THUNK_DATA OriginalThunk,
			      IN OUT PIMAGE_THUNK_DATA Thunk,
			      IN PIMAGE_EXPORT_DIRECTORY ExportDirectory,
			      IN ULONG ExportSize,
			      IN BOOLEAN Static,
			      IN PCSTR DllName)
{
    PCSTR ImportName = NULL;

    /* Check if the snap is by ordinal */
    USHORT Ordinal;
    ULONG OriginalOrdinal = 0;
    BOOLEAN IsOrdinal = IMAGE_SNAP_BY_ORDINAL(OriginalThunk->Ordinal);
    if (IsOrdinal) {
	/* Get the ordinal number, and its normalized version */
	OriginalOrdinal = IMAGE_ORDINAL(OriginalThunk->Ordinal);
	Ordinal = (USHORT)(OriginalOrdinal - ExportDirectory->Base);
    } else {
	/* First get the data VA */
	PIMAGE_IMPORT_BY_NAME AddressOfData = (PIMAGE_IMPORT_BY_NAME)
	    ((ULONG_PTR)ImportBase + (OriginalThunk->AddressOfData & 0xFFFFFFFFUL));

	/* Get the name */
	ImportName = (PCSTR)AddressOfData->Name;

	/* Now get the VA of the Name and Ordinal Tables */
	PULONG NameTable = (PULONG)((ULONG_PTR)ExportBase + ExportDirectory->AddressOfNames);
	PUSHORT OrdinalTable = (PUSHORT)((ULONG_PTR)ExportBase +
					 ExportDirectory->AddressOfNameOrdinals);

	/* Get the hint */
	USHORT Hint = AddressOfData->Hint;

	/* Try to get a match by using the hint */
	if (((ULONG)Hint < ExportDirectory->NumberOfNames) &&
	    (!strcmp(ImportName, ((PCSTR)((ULONG_PTR)ExportBase + NameTable[Hint]))))) {
	    /* We got a match, get the Ordinal from the hint */
	    Ordinal = OrdinalTable[Hint];
	} else {
	    /* Well bummer, hint didn't work, do it the long way */
	    Ordinal = LdrpNameToOrdinal(ImportName, ExportDirectory->NumberOfNames,
					ExportBase, NameTable, OrdinalTable);
	}
    }

    /* Check if the ordinal is valid */
    if ((ULONG)Ordinal < ExportDirectory->NumberOfFunctions) {
	/* The ordinal seems correct, get the AddressOfFunctions VA */
	PULONG AddressOfFunctions = (PULONG)((ULONG_PTR)ExportBase +
					     ExportDirectory->AddressOfFunctions);

	/* Write the function pointer */
	Thunk->Function = (ULONG_PTR)ExportBase + AddressOfFunctions[Ordinal];

	/* Make sure it's within the exports */
	if ((Thunk->Function > (ULONG_PTR)ExportDirectory) &&
	    (Thunk->Function < ((ULONG_PTR)ExportDirectory + ExportSize))) {
	    /* Get the Import and Forwarder Names */
	    ImportName = (PCSTR)Thunk->Function;
	    PCSTR DotPosition = strchr(ImportName, '.');
	    ASSERT(DotPosition != NULL);
	    if (!DotPosition) {
		goto FailurePath;
	    }

	    /* Load the forwarder */
	    PVOID ForwarderHandle;
	    NTSTATUS Status = LdrpLoadDll(ImportName, &ForwarderHandle);
	    /* If the load failed, use the failure path */
	    if (!NT_SUCCESS(Status))
		goto FailurePath;

	    /* Now set up a name for the actual forwarder dll */
	    ANSI_STRING ForwarderName;
	    RtlInitAnsiString(&ForwarderName, DotPosition + sizeof(CHAR));

	    /* Check if it's an ordinal forward */
	    ULONG ForwardOrdinal;
	    PANSI_STRING ForwardName;
	    if ((ForwarderName.Length > 1) && (*ForwarderName.Buffer == '#')) {
		/* We don't have an actual function name */
		ForwardName = NULL;

		/* Convert the string into an ordinal */
		Status = RtlCharToInteger(ForwarderName.Buffer + sizeof(CHAR),
					  0, &ForwardOrdinal);

		/* If this fails, then error out */
		if (!NT_SUCCESS(Status))
		    goto FailurePath;
	    } else {
		/* Import by name */
		ForwardName = &ForwarderName;
		ForwardOrdinal = 0;
	    }

	    /* Get the pointer */
	    Status = LdrGetProcedureAddress(ForwarderHandle, ForwardName, ForwardOrdinal,
					    (PVOID *)(&Thunk->Function));
	    /* If this fails, then error out */
	    if (!NT_SUCCESS(Status))
		goto FailurePath;
	} else {
	    /* It's not within the exports, let's hope it's valid */
	    if (!AddressOfFunctions[Ordinal])
		goto FailurePath;
	}
    }

    /* If we got here, then it's success */
    return STATUS_SUCCESS;

FailurePath:
    /* Is this a static snap? */
    if (Static) {
	UNICODE_STRING SnapTarget;
	PLDR_DATA_TABLE_ENTRY LdrEntry;

	/* What was the module we were searching in */
	ANSI_STRING TempString;
	RtlInitAnsiString(&TempString, DllName ? DllName : "Unknown");

	/* What was the module we were searching for */
	if (LdrpCheckForLoadedDllHandle(ImportBase, &LdrEntry)) {
	    SnapTarget = LdrEntry->BaseDllName;
	} else {
	    RtlInitUnicodeString(&SnapTarget, L"Unknown");
	}

	/* Inform the debug log */
	if (IsOrdinal) {
	    DPRINT1("Failed to snap ordinal %Z!0x%x for %wZ\n",
		    &TempString, OriginalOrdinal, &SnapTarget);
	} else {
	    DPRINT1("Failed to snap %Z!%s for %wZ\n", &TempString,
		    ImportName, &SnapTarget);
	}

	/* These are critical errors. Setup a string for the DLL name */
	ULONG_PTR HardErrorParameters[3];
	HARDERROR_RESPONSE Response;

	/* Check if we have an ordinal */
	if (IsOrdinal) {
	    /* Then set the ordinal as the 1st parameter */
	    HardErrorParameters[0] = OriginalOrdinal;
	}

	/* Raise the error */
	NtRaiseHardError(IsOrdinal ? STATUS_ORDINAL_NOT_FOUND : STATUS_ENTRYPOINT_NOT_FOUND,
			 2, 0, HardErrorParameters, OptionOk, &Response);

	/* Free our string */
	if (!IsOrdinal) {
	    /* Free our second string. Return entrypoint error */
	    return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	/* Return ordinal error */
	return STATUS_ORDINAL_NOT_FOUND;
    } else {
	/* Inform the debug log */
	if (IsOrdinal) {
	    DPRINT("Non-fatal: Failed to snap ordinal 0x%x\n",
		   OriginalOrdinal);
	} else {
	    DPRINT("Non-fatal: Failed to snap %s\n", ImportName ? ImportName : "(nil)");
	}
    }

    /* Set this as a bad DLL */
    Thunk->Function = (ULONG_PTR)0xFFBADD11UL;

    /* Return the right error code */
    return IsOrdinal ? STATUS_ORDINAL_NOT_FOUND : STATUS_ENTRYPOINT_NOT_FOUND;
}

NTSTATUS LdrGetProcedureAddress(IN PVOID BaseAddress,
				IN PANSI_STRING Name,
				IN ULONG Ordinal,
				OUT PVOID *ProcedureAddress)
{
    NTSTATUS Status = STATUS_SUCCESS;
    UCHAR ImportBuffer[64];
    PLDR_DATA_TABLE_ENTRY LdrEntry;
    IMAGE_THUNK_DATA Thunk;
    PVOID ImageBase;
    PIMAGE_IMPORT_BY_NAME ImportName = NULL;
    PIMAGE_EXPORT_DIRECTORY ExportDir;
    ULONG ExportDirSize, Length;

    DPRINT1("LDR: LdrGetProcedureAddress by ");

    /* Check if we got a name */
    if (Name) {
	DbgPrint("NAME - %s\n", Name->Buffer);

	/* Make sure it's not too long */
	Length = Name->Length + sizeof(CHAR) + FIELD_OFFSET(IMAGE_IMPORT_BY_NAME, Name);
	if (Length > UNICODE_STRING_MAX_BYTES) {
	    /* Won't have enough space to add the hint */
	    return STATUS_NAME_TOO_LONG;
	}

	/* Check if our buffer is large enough */
	if (Length > sizeof(ImportBuffer)) {
	    /* Allocate from heap, plus 2 bytes for the Hint */
	    ImportName = RtlAllocateHeap(RtlGetProcessHeap(), 0, Length);
	} else {
	    /* Use our internal buffer */
	    ImportName = (PIMAGE_IMPORT_BY_NAME)ImportBuffer;
	}

	/* Clear the hint */
	ImportName->Hint = 0;

	/* Copy the name and null-terminate it */
	RtlCopyMemory(ImportName->Name, Name->Buffer, Name->Length);
	ImportName->Name[Name->Length] = ANSI_NULL;

	/* Clear the high bit */
	ImageBase = ImportName;
	Thunk.AddressOfData = 0;
    } else {
	/* Do it by ordinal */
	ImageBase = NULL;

	DbgPrint("ORDINAL - %x\n", Ordinal);

	/* Make sure an ordinal was given */
	if (!Ordinal) {
	    /* No ordinal */
	    DPRINT1("No ordinal and no name\n");
	    return STATUS_INVALID_PARAMETER;
	}

	/* Set the original flag in the thunk */
	Thunk.Ordinal = Ordinal | IMAGE_ORDINAL_FLAG;
    }

    /* Acquire lock */
    RtlEnterCriticalSection(&LdrpLoaderLock);

    /* Try to find the loaded DLL */
    if (!LdrpCheckForLoadedDllHandle(BaseAddress, &LdrEntry)) {
	/* Invalid base */
	DPRINT1("Invalid base address %p\n", BaseAddress);
	Status = STATUS_DLL_NOT_FOUND;
	goto Quickie;
    }

    /* Get the pointer to the export directory */
    ExportDir = RtlImageDirectoryEntryToData(LdrEntry->DllBase, TRUE,
					     IMAGE_DIRECTORY_ENTRY_EXPORT,
					     &ExportDirSize);

    if (!ExportDir) {
	DPRINT1("Image %wZ has no exports, but were trying to get procedure %Z. "
		"BaseAddress asked %p, got entry BA %p\n",
		&LdrEntry->BaseDllName, Name, BaseAddress, LdrEntry->DllBase);
	Status = STATUS_PROCEDURE_NOT_FOUND;
	goto Quickie;
    }

    /* Now get the thunk */
    Status = LdrpSnapThunk(LdrEntry->DllBase, ImageBase, &Thunk, &Thunk,
			   ExportDir, ExportDirSize, FALSE, NULL);

    /* Make sure we're OK till here */
    if (NT_SUCCESS(Status)) {
	/* Return the address */
	*ProcedureAddress = (PVOID)Thunk.Function;
    }

Quickie:
    /* Cleanup */
    if (ImportName && (ImportName != (PIMAGE_IMPORT_BY_NAME)ImportBuffer)) {
	/* We allocated from heap, free it */
	RtlFreeHeap(RtlGetProcessHeap(), 0, ImportName);
    }

    /* Release the lock */
    RtlLeaveCriticalSection(&LdrpLoaderLock);

    /* We're done */
    return Status;
}

static NTSTATUS LdrpSnapIAT(IN PLDR_DATA_TABLE_ENTRY ExportLdrEntry,
			    IN PLDR_DATA_TABLE_ENTRY ImportLdrEntry,
			    IN PIMAGE_IMPORT_DESCRIPTOR IatEntry,
			    IN BOOLEAN EntriesValid)
{
    PIMAGE_THUNK_DATA OriginalThunk, FirstThunk;
    ULONG ForwarderChain;

    DPRINT("LdrpSnapIAT(%wZ %wZ %p %u)\n", &ExportLdrEntry->BaseDllName,
	   &ImportLdrEntry->BaseDllName, IatEntry, EntriesValid);

    /* Get the export directory */
    ULONG ExportSize;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory =
	RtlImageDirectoryEntryToData(ExportLdrEntry->DllBase, TRUE,
				     IMAGE_DIRECTORY_ENTRY_EXPORT, &ExportSize);
    if (!ExportDirectory) {
	DbgTrace("LDR: %wZ doesn't contain an EXPORT table\n",
		 &ExportLdrEntry->BaseDllName);
	return STATUS_INVALID_IMAGE_FORMAT;
    }

    /* Check that the image data directory contains a valid pointer to the
     * import address table. Although on Windows an image may not need to
     * specify a valid data directory entry for the IAT (because the same
     * information is contained in the import table), all modern compilers
     * generate it, so on Neptune OS this is a hard requirement. */
    ULONG IatSize;
    if (!RtlImageDirectoryEntryToData(ImportLdrEntry->DllBase, TRUE,
				      IMAGE_DIRECTORY_ENTRY_IAT, &IatSize)) {
	return STATUS_INVALID_IMAGE_FORMAT;
    }

    /* Check if the Thunks are already valid */
    if (EntriesValid) {
	/* We'll only do forwarders. Get the import name */
	PCSTR ImportName = (PCSTR)((ULONG_PTR)ImportLdrEntry->DllBase + IatEntry->Name);

	/* Get the list of forwarders */
	ForwarderChain = IatEntry->ForwarderChain;

	/* Loop them */
	while (ForwarderChain != -1) {
	    /* Get the cached thunk VA */
	    OriginalThunk = (PIMAGE_THUNK_DATA)
		((ULONG_PTR)ImportLdrEntry->DllBase + IatEntry->OriginalFirstThunk +
		 (ForwarderChain * sizeof(IMAGE_THUNK_DATA)));

	    /* Get the first thunk */
	    FirstThunk = (PIMAGE_THUNK_DATA)
		((ULONG_PTR)ImportLdrEntry->DllBase + IatEntry->FirstThunk +
		 (ForwarderChain * sizeof(IMAGE_THUNK_DATA)));

	    /* Get the Forwarder from the thunk */
	    ForwarderChain = (ULONG)FirstThunk->Ordinal;

	    /* Snap the thunk */
	    NTSTATUS Status = LdrpSnapThunk(ExportLdrEntry->DllBase,
					    ImportLdrEntry->DllBase,
					    OriginalThunk,
					    FirstThunk,
					    ExportDirectory,
					    ExportSize, TRUE, ImportName);

	    /* If we messed up, exit */
	    if (!NT_SUCCESS(Status)) {
		return Status;
	    }

	    /* Move to the next thunk */
	    FirstThunk++;
	}
    } else if (IatEntry->FirstThunk) {
	/* Full snapping. Get the First thunk */
	FirstThunk = (PIMAGE_THUNK_DATA)((ULONG_PTR)ImportLdrEntry->DllBase
					 + IatEntry->FirstThunk);

	/* Get the NT Header */
	PIMAGE_NT_HEADERS NtHeader = RtlImageNtHeader(ImportLdrEntry->DllBase);

	/* Get the Original thunk VA, watch out for weird images */
	if ((IatEntry->Characteristics < NtHeader->OptionalHeader.SizeOfHeaders)
	    || (IatEntry->Characteristics >= NtHeader->OptionalHeader.SizeOfImage)) {
	    /* Refuse it, this is a strange linked file */
	    OriginalThunk = FirstThunk;
	} else {
	    /* Get the address from the field and convert to VA */
	    OriginalThunk = (PIMAGE_THUNK_DATA)((ULONG_PTR)ImportLdrEntry->DllBase
						+ IatEntry->OriginalFirstThunk);
	}

	/* Get the Import name VA */
	PCSTR ImportName = (PCSTR)((ULONG_PTR)ImportLdrEntry->DllBase + IatEntry->Name);

	/* Loop while it's valid */
	while (OriginalThunk->AddressOfData) {
	    /* Snap the Thunk */
	    NTSTATUS Status = LdrpSnapThunk(ExportLdrEntry->DllBase,
					    ImportLdrEntry->DllBase,
					    OriginalThunk,
					    FirstThunk,
					    ExportDirectory,
					    ExportSize, TRUE, ImportName);

	    /* If we failed the snap, return */
	    if (!NT_SUCCESS(Status)) {
		return Status;
	    }

	    /* Next thunks */
	    OriginalThunk++;
	    FirstThunk++;
	}
    }

    return STATUS_SUCCESS;
}

static NTSTATUS LdrpHandleBoundDescriptor(IN PLDR_DATA_TABLE_ENTRY LdrEntry,
					  IN PIMAGE_BOUND_IMPORT_DESCRIPTOR *BoundEntryPtr,
					  IN PIMAGE_BOUND_IMPORT_DESCRIPTOR FirstEntry)
{
    PCSTR ImportName = NULL;
    BOOLEAN AlreadyLoaded = FALSE, Stale;
    PIMAGE_IMPORT_DESCRIPTOR ImportEntry;
    PLDR_DATA_TABLE_ENTRY DllLdrEntry, ForwarderLdrEntry;
    PIMAGE_BOUND_FORWARDER_REF ForwarderEntry;
    PIMAGE_BOUND_IMPORT_DESCRIPTOR BoundEntry;
    PPEB Peb = NtCurrentPeb();

    /* Get the pointer to the bound entry */
    BoundEntry = *BoundEntryPtr;

    /* Get the name's VA */
    PCSTR BoundImportName = (PCSTR) FirstEntry + BoundEntry->OffsetModuleName;

    DPRINT1("LDR: %wZ bound to %s\n", &LdrEntry->BaseDllName, BoundImportName);

    /* Load the module for this entry */
    NTSTATUS Status = LdrpLoadImportModule(BoundImportName,
					   &DllLdrEntry, &AlreadyLoaded);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("LDR: %wZ failed to load import module %s; status = %x\n",
		&LdrEntry->BaseDllName, BoundImportName, Status);
	goto Quickie;
    }

    /* Check if it wasn't already loaded */
    if (!AlreadyLoaded) {
	/* Add it to our list */
	InsertTailList(&Peb->LdrData->InInitializationOrderModuleList,
		       &DllLdrEntry->InInitializationOrderLinks);
    }

    /* Check if the Bound Entry is now invalid */
    if ((BoundEntry->TimeDateStamp != DllLdrEntry->TimeDateStamp) ||
	(DllLdrEntry->Flags & LDRP_IMAGE_NOT_AT_BASE)) {
	DPRINT1("LDR: %wZ has stale binding to %s\n",
		&LdrEntry->BaseDllName, BoundImportName);

	/* Remember it's become stale */
	Stale = TRUE;
    } else {
	DPRINT1("LDR: %wZ has correct binding to %s\n",
		&LdrEntry->BaseDllName, BoundImportName);

	/* Remember it's valid */
	Stale = FALSE;
    }

    /* Get the forwarders */
    ForwarderEntry = (PIMAGE_BOUND_FORWARDER_REF) (BoundEntry + 1);

    /* Loop them */
    for (ULONG i = 0; i < BoundEntry->NumberOfModuleForwarderRefs; i++) {
	/* Get the name */
	PCSTR ForwarderName = (PCSTR) FirstEntry + ForwarderEntry->OffsetModuleName;

	DPRINT1("LDR: %wZ bound to %s via forwarder(s) from %wZ\n",
		&LdrEntry->BaseDllName,
		ForwarderName, &DllLdrEntry->BaseDllName);

	/* Load the module */
	Status = LdrpLoadImportModule(ForwarderName, &ForwarderLdrEntry, &AlreadyLoaded);
	if (NT_SUCCESS(Status)) {
	    /* If the module was not previously loaded, add it to the list. */
	    if (!AlreadyLoaded) {
		InsertTailList(&Peb->LdrData->InInitializationOrderModuleList,
			       &ForwarderLdrEntry->InInitializationOrderLinks);
	    }
	}

	/* Check if the Bound Entry is now invalid */
	if (!NT_SUCCESS(Status)
	    || ForwarderEntry->TimeDateStamp != ForwarderLdrEntry->TimeDateStamp
	    || (ForwarderLdrEntry->Flags & LDRP_IMAGE_NOT_AT_BASE)) {
	    DPRINT1("LDR: %wZ has stale binding to %s\n",
		    &LdrEntry->BaseDllName, ForwarderName);

	    /* Remember it's become stale */
	    Stale = TRUE;
	} else {
	    DPRINT1("LDR: %wZ has correct binding to %s\n",
		    &LdrEntry->BaseDllName, ForwarderName);

	    /* Remember it's valid */
	    Stale = FALSE;
	}

	/* Move to the next one */
	ForwarderEntry++;
    }

    /* Set the next bound entry to the forwarder */
    FirstEntry = (PIMAGE_BOUND_IMPORT_DESCRIPTOR) ForwarderEntry;

    /* Check if the binding was stale */
    if (Stale) {
	ULONG IatSize;
	/* It was, so find the IAT entry for it */
	ImportEntry = RtlImageDirectoryEntryToData(LdrEntry->DllBase,
						   TRUE,
						   IMAGE_DIRECTORY_ENTRY_IMPORT,
						   &IatSize);

	/* Make sure it has a name */
	while (ImportEntry->Name) {
	    /* Get the name */
	    ImportName = (PCSTR) ((ULONG_PTR) LdrEntry->DllBase + ImportEntry->Name);

	    /* Compare it */
	    if (!strcasecmp(ImportName, BoundImportName))
		break;

	    /* Move to next entry */
	    ImportEntry++;
	}

	/* If we didn't find a name, fail */
	if (!ImportEntry->Name) {
	    DPRINT1("LDR: LdrpWalkImportTable - failing with"
		    "STATUS_OBJECT_NAME_INVALID due to no import descriptor name\n");

	    /* Return error */
	    Status = STATUS_OBJECT_NAME_INVALID;
	    goto Quickie;
	}

	DPRINT1("LDR: Stale Bind %s from %wZ\n", ImportName, &LdrEntry->BaseDllName);

	/* Snap the IAT Entry */
	Status = LdrpSnapIAT(DllLdrEntry, LdrEntry, ImportEntry, FALSE);

	/* Make sure we didn't fail */
	if (!NT_SUCCESS(Status)) {
	    DPRINT1("LDR: %wZ failed to load import module %s; status = %x\n",
		    &LdrEntry->BaseDllName, BoundImportName, Status);

	    /* Return */
	    goto Quickie;
	}
    }

    /* All done */
    Status = STATUS_SUCCESS;

Quickie:
    /* Write where we are now and return */
    *BoundEntryPtr = FirstEntry;
    return Status;
}

static NTSTATUS LdrpHandleBoundTable(IN PLDR_DATA_TABLE_ENTRY LdrEntry,
				     IN PIMAGE_BOUND_IMPORT_DESCRIPTOR BoundEntry)
{
    PIMAGE_BOUND_IMPORT_DESCRIPTOR FirstEntry = BoundEntry;

    /* Make sure we have a name */
    while (BoundEntry->OffsetModuleName) {
	/* Parse this descriptor */
	RET_ERR(LdrpHandleBoundDescriptor(LdrEntry, &BoundEntry, FirstEntry));
    }

    return STATUS_SUCCESS;
}

static NTSTATUS LdrpHandleImportDescriptor(IN PLDR_DATA_TABLE_ENTRY LdrEntry,
					   IN PIMAGE_IMPORT_DESCRIPTOR *ImportEntry)
{
    PCSTR ImportName;
    BOOLEAN AlreadyLoaded = FALSE;
    PLDR_DATA_TABLE_ENTRY DllLdrEntry;
    PIMAGE_THUNK_DATA FirstThunk;
    PPEB Peb = NtCurrentPeb();

    /* Get the import name's VA */
    ImportName = (PCSTR)((ULONG_PTR)LdrEntry->DllBase + (*ImportEntry)->Name);

    /* Get the first thunk */
    FirstThunk = (PIMAGE_THUNK_DATA)((ULONG_PTR)LdrEntry->DllBase + (*ImportEntry)->FirstThunk);

    /* Make sure it's valid */
    if (!FirstThunk->Function)
	goto SkipEntry;

    DPRINT1("LDR: %s used by %wZ\n", ImportName, &LdrEntry->BaseDllName);

    /* Load the module associated to it */
    NTSTATUS Status = LdrpLoadImportModule(ImportName, &DllLdrEntry, &AlreadyLoaded);
    if (!NT_SUCCESS(Status)) {
	DbgPrint("LDR: LdrpWalkImportTable - LdrpLoadImportModule failed "
		 "on import %s with status %x\n", ImportName, Status);
	return Status;
    }

    DPRINT1("LDR: Snapping imports for %wZ from %s\n",
	    &LdrEntry->BaseDllName, ImportName);

    /* Check if it wasn't already loaded */
    if (!AlreadyLoaded) {
	/* Add the DLL to our list */
	InsertTailList(&Peb->LdrData->InInitializationOrderModuleList,
		       &DllLdrEntry->InInitializationOrderLinks);
    }

    /* Now snap the IAT Entry */
    Status = LdrpSnapIAT(DllLdrEntry, LdrEntry, *ImportEntry, FALSE);
    if (!NT_SUCCESS(Status)) {
	DbgPrint("LDR: LdrpWalkImportTable - LdrpSnapIAT #2 failed with "
		 "status %x\n", Status);
	return Status;
    }

SkipEntry:
    /* Move on */
    (*ImportEntry)++;
    return STATUS_SUCCESS;
}

static NTSTATUS LdrpHandleImportTable(IN PLDR_DATA_TABLE_ENTRY LdrEntry,
				      IN PIMAGE_IMPORT_DESCRIPTOR ImportEntry)
{
    /* Check for Name and Thunk */
    while (ImportEntry->Name && ImportEntry->FirstThunk) {
	/* Parse this descriptor */
	RET_ERR(LdrpHandleImportDescriptor(LdrEntry, &ImportEntry));
    }

    /* Done */
    return STATUS_SUCCESS;
}

NTSTATUS LdrpWalkImportDescriptor(IN PLDR_DATA_TABLE_ENTRY LdrEntry)
{
    PIMAGE_BOUND_IMPORT_DESCRIPTOR BoundEntry = NULL;
    ULONG BoundTableSize = 0, ImportTableSize = 0;

    DbgTrace("Walking import table (%wZ loaded at %p)\n",
	     &LdrEntry->BaseDllName, LdrEntry->DllBase);

    /* Check if we were redirected */
    if (!(LdrEntry->Flags & LDRP_REDIRECTED)) {
	BoundEntry = RtlImageDirectoryEntryToData(LdrEntry->DllBase, TRUE,
						  IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT,
						  &BoundTableSize);
    }

    /* Get the regular IAT, for fallback */
    PIMAGE_IMPORT_DESCRIPTOR ImportEntry =
	RtlImageDirectoryEntryToData(LdrEntry->DllBase, TRUE,
				     IMAGE_DIRECTORY_ENTRY_IMPORT,
				     &ImportTableSize);

    if (BoundEntry) {
	RET_ERR(LdrpHandleBoundTable(LdrEntry, BoundEntry));
    } else if (ImportEntry) {
	RET_ERR(LdrpHandleImportTable(LdrEntry, ImportEntry));
    }

    return STATUS_SUCCESS;
}
