#include "psp.h"

static NTSTATUS PspThreadObjectOpenProc(PVOID Object)
{
    return STATUS_SUCCESS;
}

static NTSTATUS PspThreadObjectCloseProc(PVOID Object)
{
    return STATUS_SUCCESS;
}

static NTSTATUS PspProcessObjectOpenProc(PVOID Object)
{
    return STATUS_SUCCESS;
}

static NTSTATUS PspProcessObjectCloseProc(PVOID Object)
{
    return STATUS_SUCCESS;
}

static NTSTATUS PspCreateThreadType()
{
    OBJECT_TYPE_INITIALIZER TypeInfo =
	{
	 .CreateProc = PspThreadObjectCreateProc,
	 .OpenProc = PspThreadObjectOpenProc,
	 .CloseProc = PspThreadObjectCloseProc
	};
    return ObCreateObjectType(OBJECT_TYPE_THREAD,
			      "Thread",
			      sizeof(THREAD),
			      TypeInfo);
}

static NTSTATUS PspCreateProcessType()
{
    OBJECT_TYPE_INITIALIZER TypeInfo =
	{
	 .CreateProc = PspProcessObjectCreateProc,
	 .OpenProc = PspProcessObjectOpenProc,
	 .CloseProc = PspProcessObjectCloseProc
	};
    return ObCreateObjectType(OBJECT_TYPE_PROCESS,
			      "Process",
			      sizeof(PROCESS),
			      TypeInfo);
}

NTSTATUS PsInitSystem()
{
    RET_IF_ERR(PspCreateThreadType());
    RET_IF_ERR(PspCreateProcessType());
    return STATUS_SUCCESS;
}
