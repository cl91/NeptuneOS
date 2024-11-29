#include "psp.h"
#include <limits.h>

LIST_ENTRY PspProcessList;
PSECTION PspSystemDllSection;
PMMVAD PspUserSharedDataVad;
PMMVAD PspSystemThreadRegionVad;
PMMVAD PspClientRegionServerVad;
PMMVAD PspDriverRegionServerVad;

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
    RET_ERR(MmReserveVirtualMemory(SYSTEM_THREAD_REGION_START, SYSTEM_THREAD_REGION_END,
				   SYSTEM_THREAD_REGION_SIZE, SYSTEM_THREAD_REGION_LOW_ZERO_BITS,
				   MEM_RESERVE_BITMAP_MANAGED, &PspSystemThreadRegionVad));
    RET_ERR(MmReserveVirtualMemory(EX_CLIENT_REGION_START, EX_CLIENT_REGION_END,
				   EX_CLIENT_REGION_SIZE, EX_CLIENT_REGION_LOW_ZERO_BITS,
				   MEM_RESERVE_BITMAP_MANAGED, &PspClientRegionServerVad));
    RET_ERR(MmReserveVirtualMemory(EX_DRIVER_REGION_START, EX_DRIVER_REGION_END,
				   EX_DRIVER_REGION_SIZE, EX_DRIVER_REGION_LOW_ZERO_BITS,
				   MEM_RESERVE_BITMAP_MANAGED, &PspDriverRegionServerVad));
    InitializeListHead(&PspProcessList);
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
    return STATUS_SUCCESS;

fail:
    HalVgaPrint("\nFatal error: ");
    if (NtdllFile == NULL) {
	HalVgaPrint("%s not found", NTDLL_PATH);
    } else if (PspSystemDllSection == NULL) {
	HalVgaPrint("unable to create system dll section (error 0x%x)", Status);
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
