#include "psp.h"

LIST_ENTRY PspProcessList;
PSECTION PspSystemDllSection;
PSUBSECTION PspSystemDllTlsSubsection;

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
    PFILE_OBJECT NtdllFile = NULL;
    RET_ERR(ObReferenceObjectByName("\\BootModules\\ntdll.dll",
				    (POBJECT *) &NtdllFile));
    assert(NtdllFile != NULL);

    RET_ERR(MmCreateSection(NtdllFile, SEC_IMAGE | SEC_RESERVE | SEC_COMMIT,
			    &PspSystemDllSection));
    assert(PspSystemDllSection != NULL);
    MmDbgDumpSection(PspSystemDllSection);

    PIMAGE_SECTION_OBJECT ImageSectionObject = PspSystemDllSection->ImageSectionObject;
    LoopOverList(SubSection, &ImageSectionObject->SubSectionList, SUBSECTION, Link) {
	if (!strncmp((PCHAR) SubSection->Name, ".tls", sizeof(".tls"))) {
	    PspSystemDllTlsSubsection = SubSection;
	}
    }
    if (PspSystemDllTlsSubsection == NULL) {
	return STATUS_INVALID_IMAGE_FORMAT;
    }

    return STATUS_SUCCESS;
}

NTSTATUS PsInitSystemPhase1()
{
    RET_ERR(PspInitializeSystemDll());
    return STATUS_SUCCESS;
}
