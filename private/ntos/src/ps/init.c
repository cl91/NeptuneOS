#include "psp.h"

static NTSTATUS PspThreadObjectOpenProc(PVOID Object)
{
    return STATUS_SUCCESS;
}

static NTSTATUS PspThreadObjectParseProc(PVOID Object)
{
    return STATUS_SUCCESS;
}

static NTSTATUS PspThreadObjectInsertProc(PVOID Object)
{
    return STATUS_SUCCESS;
}

static NTSTATUS PspProcessObjectOpenProc(PVOID Object)
{
    return STATUS_SUCCESS;
}

static NTSTATUS PspProcessObjectParseProc(PVOID Object)
{
    return STATUS_SUCCESS;
}

static NTSTATUS PspProcessObjectInsertProc(PVOID Object)
{
    return STATUS_SUCCESS;
}

static NTSTATUS PspCreateThreadType()
{
    OBJECT_TYPE_INITIALIZER TypeInfo = {
	.CreateProc = PspThreadObjectCreateProc,
	.OpenProc = PspThreadObjectOpenProc,
	.ParseProc = PspThreadObjectParseProc,
	.InsertProc = PspThreadObjectInsertProc,
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
	.OpenProc = PspProcessObjectOpenProc,
	.ParseProc = PspProcessObjectParseProc,
	.InsertProc = PspProcessObjectInsertProc,
    };
    return ObCreateObjectType(OBJECT_TYPE_PROCESS,
			      "Process",
			      sizeof(PROCESS),
			      TypeInfo);
}

NTSTATUS PsInitSystem()
{
    RET_ERR(PspCreateThreadType());
    RET_ERR(PspCreateProcessType());
    return STATUS_SUCCESS;
}
