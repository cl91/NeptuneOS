#include "ei.h"

NTSTATUS ExCreateNotification(IN PVOID Object,
			      OUT LOCAL_HANDLE *Cap,
			      IN BOOLEAN ThreadLocal)
{
    if (ThreadLocal) {
	if (ObObjectGetType(Object) != OBJECT_TYPE_THREAD) {
	    assert(FALSE);
	    return STATUS_OBJECT_TYPE_MISMATCH;
	}
    } else {
	if (ObObjectGetType(Object) != OBJECT_TYPE_PROCESS) {
	    assert(FALSE);
	    return STATUS_OBJECT_TYPE_MISMATCH;
	}
    }
    PCNODE CNode = ThreadLocal ? ((PTHREAD)Object)->CSpace : ((PPROCESS)Object)->SharedCNode;
    PEX_NOTIFICATION Notification = ExAllocatePoolWithTag(sizeof(EX_NOTIFICATION),
							  NTOS_EX_TAG);
    if (!Notification) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    RET_ERR_EX(KeCreateNotificationEx(&Notification->Notification, CNode),
	       ExFreePoolWithTag(Notification, NTOS_EX_TAG));
    if (ThreadLocal) {
	InsertTailList(&((PTHREAD)Object)->NotificationList, &Notification->Link);
    } else {
	InsertTailList(&((PPROCESS)Object)->NotificationList, &Notification->Link);
    }
    ObReferenceObjectByPointer(Object);
    Notification->Object = Object;
    Notification->ThreadPrivate = ThreadLocal;
    InitializeListHead(&Notification->DeriveList);
    *Cap = Notification->Notification.TreeNode.Cap;
    return STATUS_SUCCESS;
}

VOID ExDeleteNotification(IN PEX_NOTIFICATION Notification)
{
    if (Notification->ThreadPrivate) {
	assert(ObObjectGetType(Notification->Object) == OBJECT_TYPE_THREAD);
    } else {
	assert(ObObjectGetType(Notification->Object) == OBJECT_TYPE_PROCESS);
    }
    RemoveEntryList(&Notification->Link);
    KeDestroyNotification(&Notification->Notification);
    ObDereferenceObject(Notification->Object);
    ExFreePoolWithTag(Notification, NTOS_EX_TAG);
}

NTSTATUS NtCreateNotification(IN ASYNC_STATE AsyncState,
			      IN PTHREAD Thread,
			      OUT LOCAL_HANDLE *Cap,
			      IN BOOLEAN ThreadLocal)
{
    assert(Thread != NULL);
    assert(Cap != NULL);
    PPROCESS Process = Thread->Process;
    assert(Process != NULL);
    if (ThreadLocal) {
	return ExCreateNotification(Thread, Cap, TRUE);
    } else {
	return ExCreateNotification(Process, Cap, FALSE);
    }
}
