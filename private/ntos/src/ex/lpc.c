#include "ei.h"

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
    KeInitializeSemaphore(&Port->ConnectionRequested, LONG_MAX);
    InitializeListHead(&Port->QueuedConnections);
    InsertTailList(&Ctx->ServerProcess->PortObjectList, &Port->ServerProcessLink);

    return STATUS_SUCCESS;
}

static NTSTATUS EiPortObjectOpenProc(IN ASYNC_STATE State,
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
    KeUninitializeSemaphore(&Port->ConnectionRequested);
    /* At this point there should not be any queued connections. */
    assert(!GetListLength(&Port->QueuedConnections));
    /* Also, there should not be any active connection at this point. */
    assert(!AvlGetFirstNode(&Port->Connections));
    assert((!Port->ServerProcessLink.Blink && !Port->ServerProcessLink.Flink) ||
	   (Port->ServerProcessLink.Blink && Port->ServerProcessLink.Flink));
    if (Port->ServerProcessLink.Blink) {
	RemoveEntryList(&Port->ServerProcessLink);
    }
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
    return EiCreatePortType();
}

static VOID EiDeletePortConnection(IN PLPC_PORT_CONNECTION Connection)
{
    if (Connection->ClientThread) {
	assert(ListHasEntry(&Connection->ClientThread->LpcConnectionList,
			    &Connection->ThreadLink));
	RemoveEntryList(&Connection->ThreadLink);
	ObDereferenceObject(Connection->ClientThread);
	Connection->ClientThread = NULL;
    }
    if (Connection->PortObject) {
	if (Connection->ConnectionInserted) {
	    assert(Connection->Node.Key);
	    assert(AvlTreeFindNode(&Connection->PortObject->Connections,
				   Connection->Node.Key));
	    AvlTreeRemoveNode(&Connection->PortObject->Connections,
			      &Connection->Node);
	} else {
	    assert(ListHasEntry(&Connection->PortObject->QueuedConnections, &Connection->Link));
	    RemoveEntryList(&Connection->Link);
	}
	ObDereferenceObject(Connection->PortObject);
	Connection->PortObject = NULL;
    }
    KeUninitializeEvent(&Connection->Connected);
    if (Connection->ConnectionInformation) {
	ExFreePoolWithTag(Connection->ConnectionInformation, NTOS_EX_TAG);
    }
    if (Connection->EventObject) {
	ObDereferenceObject(Connection->EventObject);
    }
    if (Connection->ReplyPort.Cap) {
	PCNODE CNode = Connection->ReplyPort.CNode;
	/* This may fail, so we ignore its error. */
	seL4_CNode_Delete(CNode->TreeNode.Cap,
			  Connection->ReplyPort.Cap, MmCNodeGetDepth(CNode));
	MmDeallocateCap(CNode, Connection->ReplyPort.Cap);
	MmUninitializeCapTreeNode(&Connection->ReplyPort);
    }
    if (Connection->ClientEndpoint.TreeNode.Cap) {
	KeDestroyEndpoint(&Connection->ClientEndpoint);
    }
    ExFreePoolWithTag(Connection, NTOS_EX_TAG);
}

/*
 * Close the port connection established by the (client) thread. This is called
 * either during (client) thread termination or when the client thread calls
 * NtDisconnectPort.
 */
VOID ExClosePortConnection(IN PLPC_PORT_CONNECTION Connection,
			   IN NTSTATUS ClientExitStatus)
{
    /* Detach the LPC port connection from the thread */
    assert(ListHasEntry(&Connection->ClientThread->LpcConnectionList,
			&Connection->ThreadLink));
    RemoveEntryList(&Connection->ThreadLink);
    /* Save the client ID so that we can notify the server to clean up.
     * Note this must be done after the link removal above, as we reuse
     * the space of ThreadLink for the client ID. */
    Connection->OldClientId.UniqueProcess =
	(HANDLE)PsGetProcessId(Connection->ClientThread->Process);
    Connection->OldClientId.UniqueThread = (HANDLE)PsGetThreadId(Connection->ClientThread);
    /* Dereference the client thread and clear its pointer in the connection object. */
    ObDereferenceObject(Connection->ClientThread);
    Connection->ClientThread = NULL;
    if (Connection->ClientEndpoint.TreeNode.Cap) {
	KeDestroyEndpoint(&Connection->ClientEndpoint);
	Connection->ClientEndpoint.TreeNode.Cap = 0;
    }
    if (Connection->ConnectionInserted) {
	AvlTreeRemoveNode(&Connection->PortObject->Connections,
			  &Connection->Node);
	Connection->ConnectionInserted = FALSE;
	/* We need to put the connection back to the queued connection list of the
	 * port object, so that the server thread can check it in NtListenPort. */
	InsertTailList(&Connection->PortObject->QueuedConnections, &Connection->Link);
    }
    /* Notify the server thread of client termination. We do not free it yet as the
     * server needs its information in order to clean up properly, unless the port
     * object itself is gone. */
    Connection->ClientExitStatus = ClientExitStatus;
    if (Connection->PortObject) {
	KeReleaseSemaphore(&Connection->PortObject->ConnectionRequested);
    } else {
	EiDeletePortConnection(Connection);
    }
}

/*
 * Close and delete the port object. This is called during server process termination.
 */
VOID ExClosePort(IN PLPC_PORT_OBJECT PortObject)
{
    /* Reference the port object so it does not get deleted too soon. */
    ObReferenceObjectByPointer(PortObject);

    /* Close all the connections that this port object has. Note if a connection is
     * inserted and has a non-zero client endpoint, it means that the client is no
     * longer waiting in NtConnectPort for the connection signal, so we should simply
     * delete the connection. If on the other hand the inserted connection has a zero
     * client endpoint cap, it means that the client is still waiting in NtConnectPort
     * for the connection signal. In this case we should wake up the client thread
     * and tell it the connection is refused. */
    PAVL_NODE Node;
    while ((Node = AvlGetFirstNode(&PortObject->Connections))) {
	PLPC_PORT_CONNECTION Connection = CONTAINING_RECORD(Node, LPC_PORT_CONNECTION, Node);
	assert(Connection->ConnectionInserted);
	assert(Connection->PortObject == PortObject);
	assert(Connection->ClientThread);
	if (Connection->ClientEndpoint.TreeNode.Cap) {
	    EiDeletePortConnection(Connection);
	} else {
	    /* Detach the connection from the port object. Note NtConnectPort does not
	     * depend on the connection having a valid port object in the failure path. */
	    AvlTreeRemoveNode(&PortObject->Connections, &Connection->Node);
	    Connection->ConnectionInserted = FALSE;
	    ObDereferenceObject(Connection->PortObject);
	    Connection->PortObject = NULL;
	    Connection->ConnectionRefused = TRUE;
	    KeSetEvent(&Connection->Connected);
	}
    }

    /* For queued connections, since the client thread is waiting for the connection
     * signal, signal the client thread, and tell it that connection failed. Note we
     * do not delete the connection yet as the client thread needs it in NtConnectPort,
     * unless the client has already died. This needs to be done before the AVL tree
     * check below, as we modify the queued connections list there. */
    LoopOverList(Connection, &PortObject->QueuedConnections, LPC_PORT_CONNECTION, Link) {
	assert(!Connection->ConnectionInserted);
	assert(Connection->PortObject == PortObject);
	if (Connection->ClientExitStatus) {
	    EiDeletePortConnection(Connection);
	} else {
	    /* Detach the connection from the port object. Note NtConnectPort does not
	     * depend on the connection having a valid port object in the failure path. */
	    RemoveEntryList(&Connection->Link);
	    ObDereferenceObject(Connection->PortObject);
	    Connection->PortObject = NULL;
	    Connection->ConnectionRefused = TRUE;
	    KeSetEvent(&Connection->Connected);
	}
    }


    /* Remove the port from the server process and dereference the port object. */
    RemoveEntryList(&PortObject->ServerProcessLink);
    ObDereferenceObject(PortObject);
}

NTSTATUS NtCreatePort(IN ASYNC_STATE AsyncState,
		      OUT HANDLE *PortHandle,
		      OUT LOCAL_HANDLE *CommPortHandle,
		      IN OPTIONAL OB_OBJECT_ATTRIBUTES ObjectAttributes,
		      IN ULONG MaxMessageLength,
		      IN OPTIONAL PSECURITY_QUALITY_OF_SERVICE SecurityQos)
{
    PTHREAD Thread = AsyncState.AsyncContext->Thread;
    assert(Thread != NULL);
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

    /* The communication port cap is in the process shared CNode. */
    *CommPortHandle = Port->Endpoint.TreeNode.Cap;
    Status = STATUS_SUCCESS;

out:
    if (RootDirectory) {
	ObDereferenceObject(RootDirectory);
    }
    if (!NT_SUCCESS(Status) && Port) {
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
		    OUT HANDLE *PortHandle,
		    IN OPTIONAL OB_OBJECT_ATTRIBUTES ObjectAttributes,
		    IN ACCESS_MASK DesiredAccess)
{
    return ObOpenObjectByName(AsyncState, ObjectAttributes,
			      OBJECT_TYPE_LPC_PORT, DesiredAccess, NULL, PortHandle);
}

NTSTATUS NtListenPort(IN ASYNC_STATE State,
		      IN HANDLE PortHandle,
		      OUT CLIENT_ID *ClientId,
		      OUT OPTIONAL PVOID ConnectionInformation,
		      IN ULONG MaxConnectionInfoLength,
		      OUT OPTIONAL ULONG *ConnectionInformationLength)
{
    assert(PortHandle);
    assert(ClientId);

    NTSTATUS Status = STATUS_NTOS_BUG;
    ASYNC_BEGIN(State, Thread, Locals, {
	    PLPC_PORT_OBJECT PortObject;
	});

    IF_ERR_GOTO(out, Status,
		ObReferenceObjectByHandle(Thread, PortHandle, OBJECT_TYPE_LPC_PORT,
					  (POBJECT *)&Locals.PortObject));

wait:
    AWAIT(Status, KeWaitForSingleObject, State, Locals,
	  &Locals.PortObject->ConnectionRequested.Header, FALSE, NULL);

    if (Status == STATUS_ASYNC_CANCELED) {
	goto out;
    }

    if (IsListEmpty(&Locals.PortObject->QueuedConnections)) {
	goto wait;
    }

    PLPC_PORT_CONNECTION Connection =
	GetIndexedElementOfList(&Locals.PortObject->QueuedConnections, 0,
				LPC_PORT_CONNECTION, Link);
    assert(Connection->PortObject == Locals.PortObject);
    if (Connection->ClientExitStatus) {
	assert(!Connection->ClientThread);
	*ClientId = Connection->OldClientId;
	Status = Connection->ClientExitStatus;
	EiDeletePortConnection(Connection);
	/* If the client thread canceled the connection request, we do not expose
	 * this event to the server thread as it should be treated as if the client
	 * did nothing. In this case we go back and wait for another connection signal. */
	if (Status == STATUS_REQUEST_CANCELED) {
	    goto wait;
	} else {
	    goto out;
	}
    }

    if (Connection->ConnectionInformation) {
	assert(Connection->ConnectionInformationLength);
	if (ConnectionInformationLength) {
	    *ConnectionInformationLength = Connection->ConnectionInformationLength;
	}
	if (MaxConnectionInfoLength < Connection->ConnectionInformationLength) {
	    Status = STATUS_BUFFER_TOO_SMALL;
	    /* We signal the ConnectionRequested semaphore so the server can try allocating
	     * a larger buffer and call NtListenPort again. */
	    KeReleaseSemaphore(&Locals.PortObject->ConnectionRequested);
	    goto out;
	}
	assert(ConnectionInformation);
	if (ConnectionInformation) {
	    RtlCopyMemory(ConnectionInformation, Connection->ConnectionInformation,
			  Connection->ConnectionInformationLength);
	}
    }

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
    RemoveEntryList(&Connection->Link);
    Connection->Node.Key = Key;
    AvlTreeInsertNode(&Locals.PortObject->Connections, Parent, &Connection->Node);
    Connection->ConnectionInserted = TRUE;
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
    PTHREAD Thread = AsyncState.AsyncContext->Thread;
    assert(Thread != NULL);
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

    /* You cannot accept or refuse a connection twice. */
    if (Connection->ConnectionAccepted || Connection->ConnectionRefused) {
	Status = STATUS_PORT_ALREADY_SET;
	goto out;
    }

    if (!AcceptConnection) {
	Status = STATUS_SUCCESS;
	goto refuse;
    }

    /* Create a per-connection-event object if the server has requested so. Note if
     * an error has occurred here, the system is likely in a very low memory state,
     * so we refuse the connection. */
    if (EventHandle) {
	IF_ERR_GOTO(refuse, Status,
		    ExCreateEvent(Thread->Process, SynchronizationEvent,
				  &Connection->EventObject, EventHandle, &Entry));
    }

    Connection->PortContext = PortContext;
    Connection->ConnectionAccepted = TRUE;
    Status = STATUS_SUCCESS;
    goto ok;

refuse:
    Connection->ConnectionRefused = TRUE;
    if (Entry) {
	ObRemoveHandle(Entry);
    }
    if (Connection->EventObject) {
	ObDereferenceObject(Connection->EventObject);
	Connection->EventObject = NULL;
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
 * Reserve a slot in one of the thread private CNodes so the server thread can
 * save the reply cap. The reply cap is a one-time capability used in the non-MCS
 * version (which we currently use) of seL4 to represent the ability for the
 * server thread to reply to its client. This slot is automatically deleted when
 * the LPC connection is closed, so server does not need to worry about cleaning
 * it up.
 */
NTSTATUS NtReserveReplyPort(IN ASYNC_STATE AsyncState,
			    IN HANDLE PortHandle,
			    IN PCLIENT_ID ClientId,
			    OUT LOCAL_HANDLE *ReplyPort)
{
    *ReplyPort = 0;
    PTHREAD Thread = AsyncState.AsyncContext->Thread;
    assert(Thread != NULL);
    PLPC_PORT_OBJECT Port = NULL;
    RET_ERR(ObReferenceObjectByHandle(Thread, PortHandle, OBJECT_TYPE_LPC_PORT,
				      (POBJECT *)&Port));

    NTSTATUS Status = STATUS_NTOS_BUG;
    PAVL_NODE Node = AvlTreeFindNode(&Port->Connections, (ULONG_PTR)ClientId->UniqueThread);
    if (!Node) {
	Status = STATUS_INVALID_CID;
	goto out;
    }
    PLPC_PORT_CONNECTION Connection = CONTAINING_RECORD(Node, LPC_PORT_CONNECTION, Node);
    assert(Node->Key == PsGetThreadId(Connection->ClientThread));
    assert(ClientId->UniqueProcess == (HANDLE)PsGetProcessId(Connection->ClientThread->Process));
    if (Connection->ReplyPort.Cap) {
	assert(Connection->ReplyPort.CNode);
	Status = STATUS_ALREADY_INITIALIZED;
	goto out;
    }

    PCNODE CNode = NULL;
    IF_ERR_GOTO(out, Status, PsRequestThreadPrivateCNode(Thread, &CNode));
    MWORD Cap = 0;
    Status = MmAllocateCap(CNode, &Cap);
    if (!NT_SUCCESS(Status)) {
	/* This is guarenteed to succeed. */
	assert(FALSE);
	goto out;
    }
    MmInitializeCapTreeNode(&Connection->ReplyPort, CAP_TREE_NODE_ENDPOINT, Cap, CNode,
			    NULL);
    *ReplyPort = PsThreadCNodeIndexToGuardedCap(CNode->TreeNode.Cap, Cap, Thread);

out:
    assert(Port);
    ObDereferenceObject(Port);
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
		       IN HANDLE PortHandle,
		       IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
		       OUT LOCAL_HANDLE *CommPortHandle,
		       OUT OPTIONAL HANDLE *EventHandle,
		       IN OUT OPTIONAL PPORT_VIEW ClientView,
		       IN OPTIONAL PISID RequiredServerSid,
		       OUT OPTIONAL REMOTE_PORT_VIEW *ServerView,
		       OUT OPTIONAL ULONG *MaxMessageLength,
		       IN OPTIONAL PVOID ConnectionInformation,
		       IN ULONG ConnectionInformationLength)
{
    NTSTATUS Status = STATUS_NTOS_BUG;
    ASYNC_BEGIN(State, Thread, Locals, {
	    PLPC_PORT_OBJECT PortObject;
	    PLPC_PORT_CONNECTION Connection;
	});
    if ((ConnectionInformation && !ConnectionInformationLength) ||
	(!ConnectionInformation && ConnectionInformationLength)) {
	ASYNC_RETURN(State, STATUS_INVALID_PARAMETER)
    }
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

    /* Also check the queued connections, because a thread can call NtConnectPort
     * multiple times in the asynchronous execution mode. We deny the subsequent
     * connection request. */
    LoopOverList(QueuedConnection, &Locals.PortObject->QueuedConnections,
		 LPC_PORT_CONNECTION, Link) {
	assert(QueuedConnection->PortObject == Locals.PortObject);
	assert(!QueuedConnection->ConnectionInserted);
	if (QueuedConnection->ClientThread == Thread) {
	    Status = STATUS_PORT_ALREADY_SET;
	    goto out;
	}
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
	    ExAllocatePoolWithTag(ConnectionInformationLength, NTOS_EX_TAG);
	if (!Locals.Connection->ConnectionInformation) {
	    ExFreePoolWithTag(Locals.Connection, NTOS_EX_TAG);
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	    goto out;
	}
	Locals.Connection->ConnectionInformationLength = ConnectionInformationLength;
	RtlCopyMemory(Locals.Connection->ConnectionInformation,
		      ConnectionInformation, ConnectionInformationLength);
    }
    Locals.Connection->PortObject = Locals.PortObject;
    ObReferenceObjectByPointer(Locals.PortObject);
    Locals.Connection->ClientThread = Thread;
    ObReferenceObjectByPointer(Thread);
    InsertHeadList(&Thread->LpcConnectionList, &Locals.Connection->ThreadLink);
    KeInitializeEvent(&Locals.Connection->Connected, SynchronizationEvent);
    InsertTailList(&Locals.PortObject->QueuedConnections, &Locals.Connection->Link);
    KeReleaseSemaphore(&Locals.PortObject->ConnectionRequested);

    AWAIT(Status, KeWaitForSingleObject, State, Locals,
	  &Locals.Connection->Connected.Header, FALSE, NULL);

    if (Status == STATUS_ASYNC_CANCELED) {
	ExClosePortConnection(Locals.Connection, STATUS_REQUEST_CANCELED);
	goto out;
    }

    assert(!Locals.Connection->ClientExitStatus);
    PHANDLE_TABLE_ENTRY Entry = NULL;
    if (Locals.Connection->ConnectionRefused) {
	Status = STATUS_CONNECTION_REFUSED;
	goto err;
    }

    if (EventHandle) {
	*EventHandle = NULL;
	if (Locals.Connection->EventObject) {
	    IF_ERR_GOTO(err, Status, ObCreateHandle(Thread->Process,
						    Locals.Connection->EventObject,
						    FALSE, EventHandle, &Entry));
	}
    }

    /* Derive the server communication endpoint with the specified badge and
     * place it into the thread-private CNode of the client thread. */
    IF_ERR_GOTO(err, Status,
		KeDeriveEndpoint(&Locals.Connection->ClientEndpoint,
				 Thread->CSpace, &Locals.PortObject->Endpoint,
				 ENDPOINT_RIGHTS_SEND_GRANTREPLY,
				 Locals.Connection->PortContext));

    *CommPortHandle =
	PsThreadCNodeIndexToGuardedCap(Locals.Connection->ClientEndpoint.TreeNode.Cap,
				       0, Thread);
    if (MaxMessageLength) {
	*MaxMessageLength = Locals.PortObject->MaxMessageLength;
    }
    Status = STATUS_SUCCESS;
    goto out;

err:
    EiDeletePortConnection(Locals.Connection);
    if (Entry) {
	ObRemoveHandle(Entry);
    }
out:
    if (Locals.PortObject) {
	ObDereferenceObject(Locals.PortObject);
    }
    ASYNC_END(State, Status);
}

/*
 * Disconnect the specified LPC communication port. This routine is called by a
 * client of an LPC connection.
 */
NTSTATUS NtDisconnectPort(IN ASYNC_STATE State,
			  IN LOCAL_HANDLE CommPortHandle)
{
    PTHREAD Thread = State.AsyncContext->Thread;
    assert(Thread != NULL);
    LoopOverList(Connection, &Thread->LpcConnectionList, LPC_PORT_CONNECTION, ThreadLink) {
	if (CommPortHandle ==
	    PsThreadCNodeIndexToGuardedCap(Connection->ClientEndpoint.TreeNode.Cap,
					   0, Thread)) {
	    assert(Connection->ConnectionInserted);
	    ExClosePortConnection(Connection, STATUS_PORT_CLOSED);
	    return STATUS_SUCCESS;
	}
    }
    return STATUS_INVALID_PARAMETER;
}
