#include "ei.h"

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
	.QueryNameProc = NULL,
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

NTSTATUS EiCreateEvent(IN PPROCESS Process,
		       IN EVENT_TYPE EventType,
		       OUT PEVENT_OBJECT *Event)
{
    EVENT_OBJ_CREATE_CONTEXT Ctx = {
	.EventType = EventType
    };
    return ObCreateObject(OBJECT_TYPE_EVENT, (POBJECT *)Event, &Ctx);
}

NTSTATUS NtCreateEvent(IN ASYNC_STATE State,
		       IN PTHREAD Thread,
                       OUT HANDLE *EventHandle,
                       IN ACCESS_MASK DesiredAccess,
                       IN OPTIONAL OB_OBJECT_ATTRIBUTES ObjectAttributes,
                       IN EVENT_TYPE EventType,
                       IN BOOLEAN InitialState)
{
    POBJECT RootDirectory = NULL;
    if (ObjectAttributes.RootDirectory) {
	RET_ERR(ObReferenceObjectByHandle(Thread, ObjectAttributes.RootDirectory,
					  OBJECT_TYPE_ANY, &RootDirectory));
    }

    NTSTATUS Status = STATUS_NTOS_BUG;
    PEVENT_OBJECT Event = NULL;
    IF_ERR_GOTO(out, Status,
		EiCreateEvent(Thread->Process, EventType, &Event));
    assert(Event != NULL);

    if (ObjectAttributes.ObjectNameBuffer && ObjectAttributes.ObjectNameBuffer[0]) {
	IF_ERR_GOTO(out, Status, ObInsertObject(RootDirectory, Event,
						ObjectAttributes.ObjectNameBuffer, 0));
    }

    IF_ERR_GOTO(out, Status, ObCreateHandle(Thread->Process, Event, FALSE, EventHandle));

    /* Even if the object is inserted into the NT namespace, NT API semantics says that
     * it is still a temporary object. */
    ObMakeTemporaryObject(Event);

    if (InitialState) {
	KeSetEvent(&Event->Event);
    }
    Status = STATUS_SUCCESS;

out:
    if (RootDirectory) {
	ObDereferenceObject(RootDirectory);
    }
    if (!NT_SUCCESS(Status)) {
	/* ObRemoveObject is a no-op if Event is not inserted. */
	ObRemoveObject(Event);
	ObDereferenceObject(Event);
    }
    return Status;
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

NTSTATUS NtOpenEvent(IN ASYNC_STATE State,
                     IN PTHREAD Thread,
                     OUT HANDLE *EventHandle,
                     IN ACCESS_MASK DesiredAccess,
                     IN OB_OBJECT_ATTRIBUTES ObjectAttributes)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    NTSTATUS Status = STATUS_NTOS_BUG;

    ASYNC_BEGIN(State);
    AWAIT_EX(Status, ObOpenObjectByName, State, _, Thread,
	     ObjectAttributes, OBJECT_TYPE_EVENT, DesiredAccess,
	     NULL, EventHandle);
    ASYNC_END(State, Status);
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
    case OBJECT_TYPE_KEY:
	/* TODO: These are all dispatcher objects. We should be
	 * able to sleep on them. This is not implemented yet. */
	assert(FALSE);
	return NULL;
    case OBJECT_TYPE_EVENT:
	return &((PEVENT_OBJECT)Object)->Event.Header;
    case OBJECT_TYPE_TIMER:
	return &((PTIMER)Object)->Header;
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
