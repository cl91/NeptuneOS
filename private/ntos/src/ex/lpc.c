#include "ei.h"

static LIST_ENTRY EiPortObjectList;

typedef struct _PORT_OBJ_CREATE_CONTEXT {
    PPROCESS ServerProcess;
    ULONG MaxMessageLength;
} PORT_OBJ_CREATE_CONTEXT, *PPORT_OBJ_CREATE_CONTEXT;

static NTSTATUS EiPortObjectCreateProc(IN POBJECT Object,
				       IN PVOID CreaCtx)
{
    PLPC_PORT_OBJECT Port = (PLPC_PORT_OBJECT)Object;
    PPORT_OBJ_CREATE_CONTEXT Ctx = (PPORT_OBJ_CREATE_CONTEXT)CreaCtx;

    RET_ERR(KeCreateEndpointEx(&Port->Endpoint, Ctx->ServerProcess->SharedCNode));
    Port->MaxMessageLength = Ctx->MaxMessageLength;
    AvlInitializeTree(&Port->Connections);
    KeInitializeEvent(&Port->ConnectionRequested, SynchronizationEvent);
    InitializeListHead(&Port->QueuedConnections);
    InsertTailList(&EiPortObjectList, &Port->Link);

    return STATUS_SUCCESS;
}

static NTSTATUS EiPortObjectOpenProc(IN ASYNC_STATE State,
				     IN PTHREAD Thread,
				     IN POBJECT Self,
				     IN PCSTR SubPath,
				     IN ACCESS_MASK DesiredAccess,
				     IN ULONG Attributes,
				     IN POB_OPEN_CONTEXT Context,
				     OUT POBJECT *pOpenedInstance,
				     OUT PCSTR *pRemainingPath)
{
    /* LPC port objects do not have sub-objects, so return error here */
    if (SubPath[0]) {
	return STATUS_OBJECT_TYPE_MISMATCH;
    }
    ObReferenceObjectByPointer(Self);
    *pOpenedInstance = Self;
    *pRemainingPath = SubPath;
    return STATUS_SUCCESS;
}

static NTSTATUS EiPortObjectCloseProc(IN ASYNC_STATE State,
				      IN PTHREAD Thread,
				      IN POBJECT Self)
{
    /* Do nothing */
    return STATUS_SUCCESS;
}

static VOID EiPortObjectDeleteProc(IN POBJECT Self)
{
    assert(ObObjectIsType(Self, OBJECT_TYPE_LPC_PORT));
    PLPC_PORT_OBJECT Port = (PLPC_PORT_OBJECT)Self;
    KeDestroyEndpoint(&Port->Endpoint);
    /* At this point the ConnectionRequested event should not be signaled. */
    assert(!Port->ConnectionRequested.Header.Signaled);
    KeUninitializeEvent(&Port->ConnectionRequested);
    /* At this point there should not be any queued connections. */
    assert(!GetListLength(&Port->QueuedConnections));
    /* Also, there should not be any active connection at this point. */
    assert(!AvlGetFirstNode(&Port->Connections));
    RemoveEntryList(&Port->Link);
}

static NTSTATUS EiCreatePortType()
{
    OBJECT_TYPE_INITIALIZER TypeInfo = {
	.CreateProc = EiPortObjectCreateProc,
	.ParseProc = NULL,
	.OpenProc = EiPortObjectOpenProc,
	.CloseProc = EiPortObjectCloseProc,
	.InsertProc = NULL,
	.RemoveProc = NULL,
	.QueryNameProc = NULL,
	.DeleteProc = EiPortObjectDeleteProc
    };
    return ObCreateObjectType(OBJECT_TYPE_LPC_PORT,
			      "LpcPort",
			      sizeof(LPC_PORT_OBJECT),
			      TypeInfo);
}

NTSTATUS EiInitPortObject()
{
    InitializeListHead(&EiPortObjectList);
    return EiCreatePortType();
}

static VOID EiDeletePortConnection(IN PLPC_PORT_CONNECTION Connection)
{
    KeUninitializeEvent(&Connection->Connected);
    if (Connection->PortObject) {
	ObDereferenceObject(Connection->PortObject);
    }
    if (Connection->ConnectionInformation) {
	ExFreePoolWithTag(Connection->ConnectionInformation, NTOS_EX_TAG);
    }
    if (Connection->EventObject) {
	ObDereferenceObject(Connection->EventObject);
    }
    ExFreePoolWithTag(Connection, NTOS_EX_TAG);
}

VOID ExClosePortConnection(IN PLPC_PORT_CONNECTION Connection,
			   IN BOOLEAN ThreadIsTerminating)
{
    /* TODO */
    if (ThreadIsTerminating) {
	
    } else {
	EiDeletePortConnection(Connection);
    }
}

NTSTATUS NtCreatePort(IN ASYNC_STATE AsyncState,
		      IN PTHREAD Thread,
		      OUT HANDLE *PortHandle,
		      OUT LOCAL_HANDLE *CommPortHandle,
		      IN OPTIONAL OB_OBJECT_ATTRIBUTES ObjectAttributes,
		      IN ULONG MaxMessageLength)
{
    POBJECT RootDirectory = NULL;
    if (ObjectAttributes.RootDirectory) {
	RET_ERR(ObReferenceObjectByHandle(Thread, ObjectAttributes.RootDirectory,
					  OBJECT_TYPE_ANY, &RootDirectory));
    }

    NTSTATUS Status = STATUS_NTOS_BUG;
    PLPC_PORT_OBJECT Port = NULL;
    PORT_OBJ_CREATE_CONTEXT Ctx = {
	.ServerProcess = Thread->Process,
	.MaxMessageLength = MaxMessageLength
    };
    IF_ERR_GOTO(out, Status,
		ObCreateObject(OBJECT_TYPE_LPC_PORT, (POBJECT *)&Port, &Ctx));
    assert(Port != NULL);

    if (ObjectAttributes.ObjectNameBuffer && ObjectAttributes.ObjectNameBuffer[0]) {
	IF_ERR_GOTO(out, Status, ObInsertObject(RootDirectory, Port,
						ObjectAttributes.ObjectNameBuffer, 0));
    }

    IF_ERR_GOTO(out, Status,
		ObCreateHandle(Thread->Process, Port, FALSE, PortHandle, NULL));

    /* Even if the object is inserted into the NT namespace, NT API semantics says that
     * it is still a temporary object. */
    ObMakeTemporaryObject(Port);

    *CommPortHandle = Port->Endpoint.TreeNode.Cap;
    Status = STATUS_SUCCESS;

out:
    if (RootDirectory) {
	ObDereferenceObject(RootDirectory);
    }
    if (!NT_SUCCESS(Status)) {
	/* ObRemoveObject is a no-op if Port is not inserted. */
	ObRemoveObject(Port);
	ObDereferenceObject(Port);
    }
    return Status;
}

/*
 * Opens the named LPC port for connection.
 */
NTSTATUS NtOpenPort(IN ASYNC_STATE AsyncState,
		    IN PTHREAD Thread,
		    OUT HANDLE *PortHandle,
		    IN OPTIONAL OB_OBJECT_ATTRIBUTES ObjectAttributes,
		    IN ACCESS_MASK DesiredAccess)
{
    return ObOpenObjectByName(AsyncState, Thread, ObjectAttributes,
			      OBJECT_TYPE_LPC_PORT, DesiredAccess, NULL, PortHandle);
}

NTSTATUS NtListenPort(IN ASYNC_STATE State,
		      IN PTHREAD Thread,
		      IN HANDLE PortHandle,
		      OUT CLIENT_ID *ClientId,
		      OUT OPTIONAL PVOID ConnectionInformation,
		      IN ULONG MaxConnectionInfoLength,
		      OUT OPTIONAL ULONG *ConnectionInformationLength)
{
    assert(Thread);
    assert(PortHandle);
    assert(ClientId);

    NTSTATUS Status = STATUS_NTOS_BUG;
    ASYNC_BEGIN(State, Locals, {
	    PLPC_PORT_OBJECT PortObject;
	});

    IF_ERR_GOTO(out, Status,
		ObReferenceObjectByHandle(Thread, PortHandle, OBJECT_TYPE_LPC_PORT,
					  (POBJECT *)&Locals.PortObject));

    AWAIT(KeWaitForSingleObject, State, Locals, Thread,
	  &Locals.PortObject->ConnectionRequested.Header, FALSE, NULL);

    assert(GetListLength(&Locals.PortObject->QueuedConnections));
    PLPC_PORT_CONNECTION Connection =
	GetIndexedElementOfList(&Locals.PortObject->QueuedConnections, 0,
				LPC_PORT_CONNECTION, Link);
    assert(Connection->PortObject == Locals.PortObject);
    if (Connection->ClientDied) {
	assert(!Connection->ClientThread);
	*ClientId = Connection->OldClientId;
	RemoveEntryList(&Connection->Link);
	EiDeletePortConnection(Connection);
	Status = STATUS_THREAD_IS_TERMINATING;
	goto out;
    }

    if (Connection->ConnectionInformation) {
	assert(Connection->ConnectionInformationLength);
	if (ConnectionInformationLength) {
	    *ConnectionInformationLength = Connection->ConnectionInformationLength;
	}
	if (MaxConnectionInfoLength < Connection->ConnectionInformationLength) {
	    Status = STATUS_BUFFER_TOO_SMALL;
	    /* We signal the ConnectionRequested event so the server can try allocating
	     * a larger buffer and call NtListenPort again. */
	    KeSetEvent(&Locals.PortObject->ConnectionRequested);
	    goto out;
	}
	assert(ConnectionInformation);
	if (ConnectionInformation) {
	    RtlCopyMemory(ConnectionInformation, Connection->ConnectionInformation,
			  Connection->ConnectionInformationLength);
	}
    }

    RemoveEntryList(&Connection->Link);
    assert(Connection->ClientThread);
    assert(ListHasEntry(&Connection->ClientThread->LpcConnectionList,
			&Connection->ThreadLink));
    ULONG64 Key = PsGetThreadId(Connection->ClientThread);
    PAVL_NODE Parent = AvlTreeFindNodeOrParent(&Locals.PortObject->Connections, Key);
    if (Parent && Parent->Key == Key) {
	assert(FALSE);
	Status = STATUS_INTERNAL_ERROR;
	goto out;
    }
    Connection->Node.Key = Key;
    AvlTreeInsertNode(&Locals.PortObject->Connections, Parent, &Connection->Node);
    Connection->ConnectionInserted = TRUE;
    if (!IsListEmpty(&Locals.PortObject->QueuedConnections)) {
	KeSetEvent(&Locals.PortObject->ConnectionRequested);
    }
    ClientId->UniqueProcess = (HANDLE)PsGetProcessId(Connection->ClientThread->Process);
    ClientId->UniqueThread = (HANDLE)PsGetThreadId(Connection->ClientThread);
    Status = STATUS_SUCCESS;

out:
    if (Locals.PortObject) {
	ObDereferenceObject(Locals.PortObject);
    }
    ASYNC_END(State, Status);
}

NTSTATUS NtAcceptPort(IN ASYNC_STATE AsyncState,
		      IN PTHREAD Thread,
		      OUT OPTIONAL HANDLE *EventHandle,
		      IN HANDLE PortHandle,
		      IN ULONG_PTR PortContext,
		      IN PCLIENT_ID ClientId,
		      IN BOOLEAN AcceptConnection,
		      IN OUT OPTIONAL PPORT_VIEW ServerView,
		      OUT OPTIONAL REMOTE_PORT_VIEW *ClientView)
{
    if (EventHandle) {
	*EventHandle = NULL;
    }
    PLPC_PORT_OBJECT Port = NULL;
    RET_ERR(ObReferenceObjectByHandle(Thread, PortHandle, OBJECT_TYPE_LPC_PORT,
				      (POBJECT *)&Port));
    NTSTATUS Status = STATUS_NTOS_BUG;
    PSECTION SectionObject = NULL;
    if (ServerView && ServerView->SectionHandle) {
	IF_ERR_GOTO(out, Status, ObReferenceObjectByHandle(Thread,
							   ServerView->SectionHandle,
							   OBJECT_TYPE_SECTION,
							   (POBJECT *)&SectionObject));
    }
    PAVL_NODE Node = AvlTreeFindNode(&Port->Connections, (ULONG_PTR)ClientId->UniqueThread);
    if (!Node) {
	Status = STATUS_INVALID_CID;
	goto out;
    }
    PHANDLE_TABLE_ENTRY Entry = NULL;
    PLPC_PORT_CONNECTION Connection = CONTAINING_RECORD(Node, LPC_PORT_CONNECTION, Node);
    assert(Node->Key == PsGetThreadId(Connection->ClientThread));
    assert(ClientId->UniqueProcess == (HANDLE)PsGetProcessId(Connection->ClientThread->Process));
    if (!AcceptConnection) {
	Status = STATUS_SUCCESS;
	goto refuse;
    }

    /* Create an event object if the server has requested so. Note if an error has
     * occurred here, the system is likely in a very low memory state, so we refuse
     * the connection. */
    if (EventHandle) {
	IF_ERR_GOTO(refuse, Status,
		    ExCreateEvent(Thread->Process, SynchronizationEvent,
				  &Connection->EventObject, EventHandle, &Entry));
    }

    Connection->PortContext = PortContext;
    Status = STATUS_SUCCESS;
    goto ok;

refuse:
    Connection->ConnectionRefused = TRUE;
    if (Entry) {
	ObRemoveHandle(Entry);
    }
ok:
    KeSetEvent(&Connection->Connected);
out:
    assert(Port);
    ObDereferenceObject(Port);
    if (SectionObject) {
	ObDereferenceObject(SectionObject);
    }
    return Status;
}

/*
 * Connect to the specified LPC port. This routine is called by a client of
 * an LPC connection.
 *
 * PortHandle is the NT handle of the LPC connection port object. On success,
 * *CommPortHandle will contain the local handle of the communication port.
 *
 * Note here SecurityQos specifies how the server can impersonate the client,
 * which is different from the SecurityQos in the OBJECT_ATTRIBUTES of the
 * port object used in NtCreatePort. The latter specifies how the client can
 * impersonate the server when opening the port object.
 */
NTSTATUS NtConnectPort(IN ASYNC_STATE State,
		       IN PTHREAD Thread,
		       IN HANDLE PortHandle,
		       IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
		       OUT LOCAL_HANDLE *CommPortHandle,
		       OUT OPTIONAL HANDLE *EventHandle,
		       IN OUT OPTIONAL PPORT_VIEW ClientView,
		       OUT OPTIONAL REMOTE_PORT_VIEW *ServerView,
		       OUT OPTIONAL ULONG *MaxMessageLength,
		       IN OPTIONAL PVOID ConnectionInformation,
		       IN ULONG ConnectionInformationLength)
{
    NTSTATUS Status = STATUS_NTOS_BUG;
    ASYNC_BEGIN(State, Locals, {
	    PLPC_PORT_OBJECT PortObject;
	    PLPC_PORT_CONNECTION Connection;
	});
    IF_ERR_GOTO(out, Status, ObReferenceObjectByHandle(Thread, PortHandle,
						       OBJECT_TYPE_LPC_PORT,
						       (POBJECT *)&Locals.PortObject));

    /* Check if we already have established a connection. In this case we deny the
     * new connection request. */
    ULONG64 Key = PsGetThreadId(Thread);
    if (AvlTreeFindNode(&Locals.PortObject->Connections, Key)) {
	Status = STATUS_PORT_ALREADY_SET;
	goto out;
    }

    /* Allocate a new LPC_PORT_CONNECTION and queue the connection. */
    Locals.Connection = ExAllocatePoolWithTag(sizeof(LPC_PORT_CONNECTION),
					      NTOS_EX_TAG);
    if (!Locals.Connection) {
	Status = STATUS_INSUFFICIENT_RESOURCES;
	goto out;
    }
    if (ConnectionInformation && ConnectionInformationLength) {
	Locals.Connection->ConnectionInformation =
	    ExAllocatePoolWithTag(ConnectionInformationLength,
				  NTOS_EX_TAG);
	if (!Locals.Connection->ConnectionInformation) {
	    ExFreePoolWithTag(Locals.Connection, NTOS_EX_TAG);
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	    goto out;
	}
	Locals.Connection->ConnectionInformationLength = ConnectionInformationLength;
    }
    Locals.Connection->PortObject = Locals.PortObject;
    ObReferenceObjectByPointer(Locals.PortObject);
    Locals.Connection->ClientThread = Thread;
    ObReferenceObjectByPointer(Thread);
    InsertHeadList(&Thread->LpcConnectionList, &Locals.Connection->ThreadLink);
    KeInitializeEvent(&Locals.Connection->Connected, SynchronizationEvent);
    InsertHeadList(&Locals.PortObject->QueuedConnections, &Locals.Connection->Link);
    KeSetEvent(&Locals.PortObject->ConnectionRequested);

    AWAIT(KeWaitForSingleObject, State, Locals, Thread,
	  &Locals.Connection->Connected.Header, FALSE, NULL);

    assert(Locals.Connection->ConnectionInserted);
    assert(!Locals.Connection->ClientDied);
    PHANDLE_TABLE_ENTRY Entry = NULL;
    if (Locals.Connection->ConnectionRefused) {
	Status = STATUS_CONNECTION_REFUSED;
	goto err;
    }

    if (EventHandle && Locals.Connection->EventObject) {
	IF_ERR_GOTO(err, Status, ObCreateHandle(Thread->Process,
						Locals.Connection->EventObject,
						FALSE, EventHandle, &Entry));
    }

    /* Derive the server communication endpoint with the specified badge and
     * place it into the thread-private CNode of the client thread. */
    IF_ERR_GOTO(err, Status,
		KeDeriveEndpoint(&Locals.Connection->ClientEndpoint,
				 Thread->CSpace, &Locals.PortObject->Endpoint,
				 ENDPOINT_RIGHTS_SEND,
				 Locals.Connection->PortContext));

    *CommPortHandle =
	PsThreadCNodeIndexToGuardedCap(Locals.Connection->ClientEndpoint.TreeNode.Cap,
				       0, Thread);
    Status = STATUS_SUCCESS;
    goto out;

err:
    ExClosePortConnection(Locals.Connection, FALSE);
    if (Entry) {
	ObRemoveHandle(Entry);
    }
out:
    if (Locals.PortObject) {
	ObDereferenceObject(Locals.PortObject);
    }
    ASYNC_END(State, Status);
}
