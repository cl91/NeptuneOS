#include "psp.h"

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

NTSTATUS PsInitSystem()
{
    RET_ERR(PspCreateThreadType());
    RET_ERR(PspCreateProcessType());
    return STATUS_SUCCESS;
}
