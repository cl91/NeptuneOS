#include "psp.h"

LIST_ENTRY PspProcessList;
PSECTION PspSystemDllSection;
PSUBSECTION PspSystemDllTlsSubsection;
PMMVAD PspUserSharedDataVad;
MWORD PspUserExceptionDispatcherAddress;

static NTSTATUS PspCreateThreadType()
{
    OBJECT_TYPE_INITIALIZER TypeInfo = {
	.CreateProc = PspThreadObjectCreateProc,
	.OpenProc = NULL,
	.ParseProc = NULL,
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
	.OpenProc = NULL,
	.ParseProc = NULL,
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
 * This is the same as LdrpNameToOrdinal except we assume that the DLL
 * is mapped as ordinary file as opposed to image (therefore we need to
 * convert RVA to file offset).
 */
static USHORT PspNameToOrdinal(IN PCSTR ExportName,
			       IN ULONG NumberOfNames,
			       IN PVOID DllBase,
			       IN PIMAGE_NT_HEADERS NtHeader,
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
	CmpResult = strcmp(ExportName,
			   (PCHAR)RtlImageRvaToVa(NtHeader, DllBase,
						  NameTable[Next], NULL));

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

/*
 * This is a simplified version of LdrGetProcedureAddress. For the given
 * DLL at DllBase (mapped as ordinary file, not as image) we return the
 * relative virtual address of the given exported symbol.
 */
static NTSTATUS PspLookupExportRva(IN PVOID DllBase,
				   IN PCSTR NameOfExport,
				   OUT ULONG *ExportRva)
{
    /* Get the image NT header */
    PIMAGE_NT_HEADERS NtHeader = RtlImageNtHeader(DllBase);

    /* Get the pointer to the export directory */
    ULONG ExportSize = 0;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)
        RtlImageDirectoryEntryToData(DllBase, FALSE,
				     IMAGE_DIRECTORY_ENTRY_EXPORT,
				     &ExportSize);
    assert(ExportDirectory != NULL);
    assert(ExportSize != 0);

    /* Get the pointer to the Names table */
    PULONG AddressOfNames = (PULONG)RtlImageRvaToVa(NtHeader, DllBase,
						    ExportDirectory->AddressOfNames,
						    NULL);

    /* Get the pointer to the NameOrdinals table */
    PUSHORT AddressOfNameOrdinals = (PUSHORT)RtlImageRvaToVa(NtHeader, DllBase,
							     ExportDirectory->AddressOfNameOrdinals,
							     NULL);

    /* Find the ordinal corresponding to the export symbol name */
    USHORT Ordinal = PspNameToOrdinal(NameOfExport,
				      ExportDirectory->NumberOfNames,
				      DllBase, NtHeader,
				      AddressOfNames,
				      AddressOfNameOrdinals);

    /* Ordinal lies outside of the export address table. Return error. */
    if ((ULONG)Ordinal >= ExportDirectory->NumberOfFunctions) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    /* Get the pointer to the export address table */
    PULONG AddressOfFunctions = (PULONG)RtlImageRvaToVa(NtHeader, DllBase,
							ExportDirectory->AddressOfFunctions,
							NULL);
    *ExportRva = AddressOfFunctions[Ordinal];
    return STATUS_SUCCESS;
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
    IF_ERR_GOTO(fail, Status, PspLookupExportRva(NtdllFile->Fcb->BufferPtr,
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
    UNUSED PKUSER_SHARED_DATA Data = (PKUSER_SHARED_DATA) PspUserSharedDataVad->AvlNode.Key;
    /* TODO */
}

PKUSER_SHARED_DATA PsGetUserSharedData()
{
    if (PspUserSharedDataVad == NULL) {
	return NULL;
    }
    return (PKUSER_SHARED_DATA) PspUserSharedDataVad->AvlNode.Key;
}

NTSTATUS PspMapUserSharedData()
{
    PMMVAD Vad = NULL;
    RET_ERR(MmReserveVirtualMemory(EX_DYN_VSPACE_START,
				   EX_DYN_VSPACE_END,
				   sizeof(KUSER_SHARED_DATA),
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
