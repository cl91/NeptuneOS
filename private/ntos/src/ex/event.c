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
    KeDestroyEvent(&Event->Event);
    RemoveEntryList(&Event->Link);
}

static NTSTATUS EiCreateEventType()
{
    OBJECT_TYPE_INITIALIZER TypeInfo = {
	.CreateProc = EiEventObjectCreateProc,
	.OpenProc = NULL,
	.ParseProc = NULL,
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
    RET_ERR(ObCreateObject(OBJECT_TYPE_EVENT, (POBJECT *)&Event,
			   NULL, NULL, 0, &Ctx));
    assert(Event != NULL);
    RET_ERR_EX(ObCreateHandle(Thread->Process, Event, EventHandle),
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
    UNIMPLEMENTED;
}

NTSTATUS NtResetEvent(IN ASYNC_STATE State,
		      IN PTHREAD Thread,
		      IN HANDLE EventHandle,
		      OUT OPTIONAL LONG *PreviousState)
{
    UNIMPLEMENTED;
}

NTSTATUS NtClearEvent(IN ASYNC_STATE State,
		      IN PTHREAD Thread,
		      IN HANDLE EventHandle)
{
    UNIMPLEMENTED;
}

NTSTATUS NtWaitForSingleObject(IN ASYNC_STATE State,
			       IN PTHREAD Thread,
                               IN HANDLE ObjectHandle,
                               IN BOOLEAN Alertable,
                               IN OPTIONAL PLARGE_INTEGER TimeOut)
{
    UNIMPLEMENTED;
}
