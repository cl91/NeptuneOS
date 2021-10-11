#include "psp.h"

LIST_ENTRY PspProcessList;
PSECTION PspSystemDllSection;
PSUBSECTION PspSystemDllTlsSubsection;
PMMVAD PspUserSharedDataVad;

static NTSTATUS PspCreateThreadType()
{
    OBJECT_TYPE_INITIALIZER TypeInfo = {
	.CreateProc = PspThreadObjectCreateProc,
	.OpenProc = NULL,
	.ParseProc = NULL,
	.InsertProc = NULL,
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

static NTSTATUS PspInitializeSystemDll()
{
    /* Create the NTDLL.DLL image section */
    PIO_FILE_OBJECT NtdllFile = NULL;
    NTSTATUS Status = ObReferenceObjectByName(NTDLL_PATH,
					      (POBJECT *) &NtdllFile);
    if (!NT_SUCCESS(Status)) {
	goto fail;
    }
    assert(NtdllFile != NULL);

    Status = MmCreateSection(NtdllFile, SEC_IMAGE | SEC_RESERVE | SEC_COMMIT,
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

    return STATUS_SUCCESS;

 fail:
    KeVgaPrint("\nFatal error: ");
    if (NtdllFile == NULL) {
	KeVgaPrint("%s not found", NTDLL_PATH);
    } else if (PspSystemDllSection == NULL) {
	KeVgaPrint("unable to create system dll section (error 0x%x)", Status);
    } else if (PspSystemDllTlsSubsection == NULL) {
	KeVgaPrint("ntdll.dll is invalid (missing .tls section)");
    }
    KeVgaPrint("\n\n");
    return Status;
}

VOID PspPopulateUserSharedData()
{
    PKUSER_SHARED_DATA Data = (PKUSER_SHARED_DATA) PspUserSharedDataVad->AvlNode.Key;
    /* TODO */
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
