#include "ei.h"

NTSTATUS NtSetThreadHardErrorPort(IN ASYNC_STATE AsyncState,
				  IN PTHREAD CallingThread,
				  IN HANDLE ThreadHandle,
				  IN LOCAL_HANDLE HardErrorPort)
{
    PTHREAD ThreadObject = NULL;
    RET_ERR(ObReferenceObjectByHandle(CallingThread, ThreadHandle,
				      OBJECT_TYPE_THREAD, (POBJECT *)&ThreadObject));
    assert(ThreadObject != NULL);
    ThreadObject->HardErrorPort = HardErrorPort;
    ObDereferenceObject(ThreadObject);
    return STATUS_SUCCESS;
}

NTSTATUS NtGetThreadHardErrorPort(IN ASYNC_STATE AsyncState,
				  IN PTHREAD CallingThread,
				  IN HANDLE ThreadHandle,
				  OUT LOCAL_HANDLE *HardErrorPort)
{
    PTHREAD ThreadObject = NULL;
    RET_ERR(ObReferenceObjectByHandle(CallingThread, ThreadHandle,
				      OBJECT_TYPE_THREAD, (POBJECT *)&ThreadObject));
    assert(ThreadObject != NULL);
    *HardErrorPort = ThreadObject->HardErrorPort;
    ObDereferenceObject(ThreadObject);
    return STATUS_SUCCESS;
}
