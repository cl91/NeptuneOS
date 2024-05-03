#include "ei.h"
#include "ob.h"

static LIST_ENTRY EiEventObjectList;

typedef struct _EVENT_OBJ_CREATE_CONTEXT {
    EVENT_TYPE EventType;
} EVENT_OBJ_CREATE_CONTEXT, *PEVENT_OBJ_CREATE_CONTEXT;

static NTSTATUS EiEventObjectCreateProc(IN POBJECT Object,
					IN PVOID CreaCtx)
{
    PEVENT_OBJECT Event = (PEVENT_OBJECT)Object;
    PEVENT_OBJ_CREATE_CONTEXT Ctx = (PEVENT_OBJ_CREATE_CONTEXT)CreaCtx;

    KeInitializeEvent(&Event->Event, Ctx->EventType);
    InsertTailList(&EiEventObjectList, &Event->Link);

    return STATUS_SUCCESS;
}

static VOID EiEventObjectDeleteProc(IN POBJECT Self)
{
    assert(ObObjectIsType(Self, OBJECT_TYPE_EVENT));
    PEVENT_OBJECT Event = (PEVENT_OBJECT)Self;
    KeUninitializeEvent(&Event->Event);
    RemoveEntryList(&Event->Link);
}

static NTSTATUS EiCreateEventType()
{
    OBJECT_TYPE_INITIALIZER TypeInfo = {
	.CreateProc = EiEventObjectCreateProc,
	.ParseProc = NULL,
	.OpenProc = NULL,
	.CloseProc = NULL,
	.InsertProc = NULL,
	.RemoveProc = NULL,
	.DeleteProc = EiEventObjectDeleteProc
    };
    return ObCreateObjectType(OBJECT_TYPE_EVENT,
			      "Event",
			      sizeof(EVENT_OBJECT),
			      TypeInfo);
}

NTSTATUS EiInitEventObject()
{
    InitializeListHead(&EiEventObjectList);
    return EiCreateEventType();
}

NTSTATUS NtCreateEvent(IN ASYNC_STATE State,
		       IN PTHREAD Thread,
                       OUT HANDLE *EventHandle,
                       IN ACCESS_MASK DesiredAccess,
                       IN OPTIONAL OB_OBJECT_ATTRIBUTES ObjectAttributes,
                       IN EVENT_TYPE EventType,
                       IN BOOLEAN InitialState)
{
    PEVENT_OBJECT Event = NULL;
    EVENT_OBJ_CREATE_CONTEXT Ctx = {
	.EventType = EventType
    };
    RET_ERR(ObCreateObject(OBJECT_TYPE_EVENT, (POBJECT *)&Event, &Ctx));
    assert(Event != NULL);
    RET_ERR_EX(ObCreateHandle(Thread->Process, Event, FALSE, EventHandle),
	       ObDereferenceObject(Event));
    if (InitialState) {
	KeSetEvent(&Event->Event);
    }
    return STATUS_SUCCESS;
}

NTSTATUS NtSetEvent(IN ASYNC_STATE State,
		    IN PTHREAD Thread,
                    IN HANDLE EventHandle,
                    OUT OPTIONAL LONG *PreviousState)
{
    PEVENT_OBJECT EventObject = NULL;
    RET_ERR(ObReferenceObjectByHandle(Thread, EventHandle, OBJECT_TYPE_EVENT,
				      (POBJECT *)&EventObject));
    assert(EventObject != NULL);
    if (PreviousState) {
	*PreviousState = EventObject->Event.Header.Signaled;
    }
    KeSetEvent(&EventObject->Event);
    ObDereferenceObject(EventObject);
    return STATUS_SUCCESS;
}

NTSTATUS NtResetEvent(IN ASYNC_STATE State,
		      IN PTHREAD Thread,
		      IN HANDLE EventHandle,
		      OUT OPTIONAL LONG *PreviousState)
{
    PEVENT_OBJECT EventObject = NULL;
    RET_ERR(ObReferenceObjectByHandle(Thread, EventHandle, OBJECT_TYPE_EVENT,
				      (POBJECT *)&EventObject));
    assert(EventObject != NULL);
    if (PreviousState) {
	*PreviousState = EventObject->Event.Header.Signaled;
    }
    KeResetEvent(&EventObject->Event);
    ObDereferenceObject(EventObject);
    return STATUS_SUCCESS;
}

NTSTATUS NtClearEvent(IN ASYNC_STATE State,
		      IN PTHREAD Thread,
		      IN HANDLE EventHandle)
{
    PEVENT_OBJECT EventObject = NULL;
    RET_ERR(ObReferenceObjectByHandle(Thread, EventHandle, OBJECT_TYPE_EVENT,
				      (POBJECT *)&EventObject));
    assert(EventObject != NULL);
    KeResetEvent(&EventObject->Event);
    ObDereferenceObject(EventObject);
    return STATUS_SUCCESS;
}

/* If the object is a dispatcher object, return the dispatcher header.
 * Otherwise return NULL. */
static PDISPATCHER_HEADER EiObjectGetDispatcherHeader(POBJECT Object)
{
    switch (ObObjectGetType(Object)) {
    case OBJECT_TYPE_DIRECTORY:
    case OBJECT_TYPE_THREAD:
    case OBJECT_TYPE_SECTION:
    case OBJECT_TYPE_FILE:
    case OBJECT_TYPE_DEVICE:
    case OBJECT_TYPE_DRIVER:
    case OBJECT_TYPE_TIMER:
    case OBJECT_TYPE_KEY:
	/* TODO: These are all dispatcher objects. We should be
	 * able to sleep on them. This is not implemented yet. */
	assert(FALSE);
	return NULL;
    case OBJECT_TYPE_EVENT:
	return &((PEVENT_OBJECT)Object)->Event.Header;
    case OBJECT_TYPE_PROCESS:
	return &((PPROCESS)Object)->Header;
    case OBJECT_TYPE_SYMBOLIC_LINK:
	/* Symbolic links are not dispatcher objects. */
	return NULL;
    case OBJECT_TYPE_SYSTEM_ADAPTER:
	/* System adapters are not dispatcher objects. */
	return NULL;
    default:
	/* This should never happen. Either we added a new object
	 * type and forgot to update the cases above, or something
	 * is seriously wrong. */
	assert(FALSE);
	return NULL;
    }
}

NTSTATUS NtWaitForSingleObject(IN ASYNC_STATE State,
			       IN PTHREAD Thread,
                               IN HANDLE ObjectHandle,
                               IN BOOLEAN Alertable,
                               IN OPTIONAL PLARGE_INTEGER TimeOut)
{
    NTSTATUS Status;
    ASYNC_BEGIN(State, Locals, {
	    POBJECT Object;
	    PDISPATCHER_HEADER DispatcherObject;
	});
    ASYNC_RET_ERR(State, ObReferenceObjectByHandle(Thread, ObjectHandle,
						   OBJECT_TYPE_ANY, &Locals.Object));
    /* We cannot deference the object now because if we did, during the wait below
     * someone else might be able to delete the object. */
    Locals.DispatcherObject = EiObjectGetDispatcherHeader(Locals.Object);
    if (!Locals.DispatcherObject) {
	ObDereferenceObject(Locals.Object);
	ASYNC_RETURN(State, STATUS_OBJECT_TYPE_MISMATCH);
    }

    AWAIT_EX(Status, KeWaitForSingleObject, State, Locals,
	     Thread, Locals.DispatcherObject, Alertable, TimeOut);
    ObDereferenceObject(Locals.Object);
    ASYNC_END(State, Status);
}
