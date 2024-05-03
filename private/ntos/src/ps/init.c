#include "psp.h"
#include <limits.h>

LIST_ENTRY PspProcessList;
PSECTION PspSystemDllSection;
PSUBSECTION PspSystemDllTlsSubsection;
PMMVAD PspUserSharedDataVad;
MWORD PspUserExceptionDispatcherAddress;

static NTSTATUS PspCreateThreadType()
{
    OBJECT_TYPE_INITIALIZER TypeInfo = {
	.CreateProc = PspThreadObjectCreateProc,
	.ParseProc = NULL,
	.OpenProc = NULL,
	.CloseProc = NULL,
	.InsertProc = NULL,
	.RemoveProc = NULL,
	.DeleteProc = PspThreadObjectDeleteProc,
    };
    return ObCreateObjectType(OBJECT_TYPE_THREAD,
			      "Thread",
			      sizeof(THREAD),
			      TypeInfo);
}

static NTSTATUS PspCreateProcessType()
{
    OBJECT_TYPE_INITIALIZER TypeInfo = {
	.CreateProc = PspProcessObjectCreateProc,
	.ParseProc = NULL,
	.OpenProc = NULL,
	.CloseProc = NULL,
	.InsertProc = NULL,
	.RemoveProc = NULL,
	.DeleteProc = PspProcessObjectDeleteProc,
    };
    return ObCreateObjectType(OBJECT_TYPE_PROCESS,
			      "Process",
			      sizeof(PROCESS),
			      TypeInfo);
}

NTSTATUS PsInitSystemPhase0()
{
    RET_ERR(PspCreateThreadType());
    RET_ERR(PspCreateProcessType());
    InitializeListHead(&PspProcessList);
    return STATUS_SUCCESS;
}

/*
 * Convert the given exported symbol name to its ordinal.
 */
static ULONG PspNameToOrdinal(IN PIO_FILE_OBJECT FileObject,
			      IN PCSTR ExportName,
			      IN ULONG NumberOfNames,
			      IN ULONG64 NamesTableOffset,
			      IN ULONG64 OrdinalsOffset)
{
    ULONG NameLength = strlen(ExportName);
    PspAllocateArray(NameBuffer, CHAR, NameLength + 1);

    /* Use classical binary search to find the ordinal */
    LONG Start = 0, Next = 0, End = NumberOfNames - 1;
    while (End >= Start) {
	/* Next will be exactly between Start and End */
	Next = (Start + End) >> 1;

	/* Call the cache manager to read the ULONG at NamesTable[Next], which
	 * will contain the RVA of the name string. */
	ULONG NameRva = 0;
	NTSTATUS Status = CcCopyRead(FileObject->Fcb, NamesTableOffset + Next * sizeof(ULONG),
				     sizeof(ULONG), (PVOID)&NameRva);
	if (!NT_SUCCESS(Status)) {
	    goto err;
	}
	/* Convert the RVA of the name string to file offset and call the cache
	 * manager to read the string pointed to by the file offset. */
	ULONG64 NameFileOffset = RtlImageRvaToFileOffset(FileObject, NameRva);
	if (!NameFileOffset) {
	    goto err;
	}
	Status = CcCopyRead(FileObject->Fcb, NameFileOffset, NameLength + 1, NameBuffer);
	if (!NT_SUCCESS(Status)) {
	    goto err;
	}

	LONG CmpResult = strcmp(ExportName, NameBuffer);
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
	goto err;

    /* Return the ordinal corresponding to the specified export name */
    USHORT Ordinal = -1;
    NTSTATUS Status = CcCopyRead(FileObject->Fcb, OrdinalsOffset + Next * sizeof(USHORT),
				 sizeof(USHORT), (PVOID)&Ordinal);
    if (!NT_SUCCESS(Status)) {
	goto err;
    }
    return Ordinal;

err:
    PspFreePool(NameBuffer);
    return ULONG_MAX;
}

/*
 * Similar to the client-side LdrGetProcedureAddress, this routine returns
 * the relative virtual address for the given exported symbol in the PE
 * image file.
 */
static NTSTATUS PspLookupExportRva(IN PIO_FILE_OBJECT FileObject,
				   IN PCSTR NameOfExport,
				   OUT ULONG *ExportRva)
{
    /* Get the pointer to the export directory */
    ULONG ExportSize = 0;
    ULONG64 ExpDirOffset = RtlImageDirectoryEntryToFileOffset(FileObject,
							      IMAGE_DIRECTORY_ENTRY_EXPORT,
							      &ExportSize);
    if (!ExportSize || !ExpDirOffset) {
	return STATUS_INVALID_IMAGE_FORMAT;
    }
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    RET_ERR(CcMapData(FileObject->Fcb, ExpDirOffset, sizeof(IMAGE_EXPORT_DIRECTORY),
		      NULL, (PVOID *)&ExportDirectory));
    assert(ExportDirectory);

    /* Get the file offset to the Names table */
    ULONG64 NamesTableOffset = RtlImageRvaToFileOffset(FileObject,
						       ExportDirectory->AddressOfNames);
    if (!NamesTableOffset) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    /* Get the file offset to the NameOrdinals table */
    ULONG64 OrdinalsOffset = RtlImageRvaToFileOffset(FileObject,
						     ExportDirectory->AddressOfNameOrdinals);
    if (!OrdinalsOffset) {
	return STATUS_PROCEDURE_NOT_FOUND;
    }

    /* Find the ordinal corresponding to the export symbol name */
    ULONG Ordinal = PspNameToOrdinal(FileObject, NameOfExport,
				     ExportDirectory->NumberOfNames,
				     NamesTableOffset, OrdinalsOffset);

    /* Ordinal lies outside of the export address table. Return error. */
    if (Ordinal >= ExportDirectory->NumberOfFunctions) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    /* Get the file offset to the export address table */
    ULONG64 AddrTableOffset = RtlImageRvaToFileOffset(FileObject,
						      ExportDirectory->AddressOfFunctions);
    if (!AddrTableOffset) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    /* Call the cache manager to read the RVA at the ordinal */
    return CcCopyRead(FileObject->Fcb, AddrTableOffset + Ordinal * sizeof(ULONG),
		      sizeof(ULONG), ExportRva);
}

static NTSTATUS PspInitializeSystemDll()
{
    /* Create the NTDLL.DLL image section */
    PIO_FILE_OBJECT NtdllFile = NULL;
    NTSTATUS Status = ObReferenceObjectByName(NTDLL_PATH, OBJECT_TYPE_FILE, NULL,
					      TRUE, (POBJECT *) &NtdllFile);
    if (!NT_SUCCESS(Status)) {
	goto fail;
    }
    assert(NtdllFile != NULL);

    Status = MmCreateSection(NtdllFile, 0, SEC_IMAGE | SEC_RESERVE | SEC_COMMIT,
			     &PspSystemDllSection);
    if (!NT_SUCCESS(Status)) {
	goto fail;
    }
    assert(PspSystemDllSection != NULL);

    PIMAGE_SECTION_OBJECT ImageSectionObject = PspSystemDllSection->ImageSectionObject;
    LoopOverList(SubSection, &ImageSectionObject->SubSectionList, SUBSECTION, Link) {
	if (!strncmp((PCHAR) SubSection->Name, ".tls", sizeof(".tls"))) {
	    PspSystemDllTlsSubsection = SubSection;
	}
    }
    if (PspSystemDllTlsSubsection == NULL) {
	Status = STATUS_INVALID_IMAGE_FORMAT;
	goto fail;
    }

    ULONG ExportRva = 0;
    IF_ERR_GOTO(fail, Status, PspLookupExportRva(NtdllFile,
						 USER_EXCEPTION_DISPATCHER_NAME,
						 &ExportRva));
    assert(ExportRva != 0);
    PspUserExceptionDispatcherAddress = ImageSectionObject->ImageBase + ExportRva;

    return STATUS_SUCCESS;

fail:
    HalVgaPrint("\nFatal error: ");
    if (NtdllFile == NULL) {
	HalVgaPrint("%s not found", NTDLL_PATH);
    } else if (PspSystemDllSection == NULL) {
	HalVgaPrint("unable to create system dll section (error 0x%x)", Status);
    } else if (PspSystemDllTlsSubsection == NULL) {
	HalVgaPrint("ntdll.dll is invalid (missing .tls section)");
    } else if (ExportRva == 0) {
	HalVgaPrint("ntdll.dll is invalid (missing export "
		    USER_EXCEPTION_DISPATCHER_NAME ")");
    }
    HalVgaPrint("\n\n");
    return Status;
}

static VOID PspPopulateUserSharedData()
{
    PKUSER_SHARED_DATA Data = (PKUSER_SHARED_DATA)PspUserSharedDataVad->AvlNode.Key;
    RtlCopyMemory(Data->NtSystemRoot, INITIAL_SYSTEM_ROOT_U, sizeof(INITIAL_SYSTEM_ROOT_U));
}

PKUSER_SHARED_DATA PsGetUserSharedData()
{
    if (PspUserSharedDataVad == NULL) {
	return NULL;
    }
    return (PKUSER_SHARED_DATA)PspUserSharedDataVad->AvlNode.Key;
}

NTSTATUS PspMapUserSharedData()
{
    PMMVAD Vad = NULL;
    RET_ERR(MmReserveVirtualMemory(EX_DYN_VSPACE_START,
				   EX_DYN_VSPACE_END,
				   sizeof(KUSER_SHARED_DATA),
				   0,
				   MEM_RESERVE_OWNED_MEMORY,
				   &Vad));
    assert(Vad != NULL);
    RET_ERR(MmCommitVirtualMemory(Vad->AvlNode.Key,
				  sizeof(KUSER_SHARED_DATA)));
    PspUserSharedDataVad = Vad;
    return STATUS_SUCCESS;
}

NTSTATUS PsInitSystemPhase1()
{
    RET_ERR(PspInitializeSystemDll());
    RET_ERR(PspMapUserSharedData());
    PspPopulateUserSharedData();
    return STATUS_SUCCESS;
}
