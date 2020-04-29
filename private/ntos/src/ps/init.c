#include "psp.h"

static NTSTATUS PspThreadTypeCreateProc(POBJECT_TYPE ObjectType)
{
    return STATUS_SUCCESS;
}

static NTSTATUS PspThreadObjectOpenProc(POBJECT_HEADER ObjectHeader)
{
    return STATUS_SUCCESS;
}

static NTSTATUS PspThreadObjectCloseProc(POBJECT_HEADER ObjectHeader)
{
    return STATUS_SUCCESS;
}

OBJECT_TYPE_INITIALIZER PspThreadInitProcs =
    {
     .TypeCreateProc = PspThreadTypeCreateProc,
     .OpenProc = PspThreadObjectOpenProc,
     .CloseProc = PspThreadObjectCloseProc
    };

static NTSTATUS PspProcessTypeCreateProc(POBJECT_TYPE ObjectType)
{
    return STATUS_SUCCESS;
}

static NTSTATUS PspProcessObjectOpenProc(POBJECT_HEADER ObjectHeader)
{
    return STATUS_SUCCESS;
}

static NTSTATUS PspProcessObjectCloseProc(POBJECT_HEADER ObjectHeader)
{
    return STATUS_SUCCESS;
}

OBJECT_TYPE_INITIALIZER PspProcessInitProcs =
    {
     .TypeCreateProc = PspProcessTypeCreateProc,
     .OpenProc = PspProcessObjectOpenProc,
     .CloseProc = PspProcessObjectCloseProc
    };

static NTSTATUS PspCreateThreadType()
{
    return ObCreateObjectType(OBJECT_TYPE_THREAD,
			      "Thread",
			      &PspThreadInitProcs);
}

static NTSTATUS PspCreateProcessType()
{
    return ObCreateObjectType(OBJECT_TYPE_PROCESS,
			      "Process",
			      &PspThreadInitProcs);
}

NTSTATUS PsInitialize()
{
    RET_IF_ERR(PspCreateThreadType());
    RET_IF_ERR(PspCreateProcessType());
    return STATUS_SUCCESS;
}
