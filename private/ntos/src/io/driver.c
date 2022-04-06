#include "iop.h"

NTSTATUS IopDriverObjectCreateProc(IN POBJECT Object,
				   IN PVOID CreaCtx)
{
    PIO_DRIVER_OBJECT Driver = (PIO_DRIVER_OBJECT) Object;
    PDRIVER_OBJ_CREATE_CONTEXT Ctx = (PDRIVER_OBJ_CREATE_CONTEXT)CreaCtx;
    PCSTR DriverToLoad = Ctx->DriverImagePath;
    PCSTR DriverName = Ctx->DriverName;
    Driver->DriverImagePath = RtlDuplicateString(DriverToLoad, NTOS_IO_TAG);
    Driver->DriverRegistryPath = RtlDuplicateString(Ctx->DriverServicePath, NTOS_IO_TAG);
    if (Driver->DriverImagePath == NULL || Driver->DriverRegistryPath == NULL) {
	return STATUS_NO_MEMORY;
    }
    InitializeListHead(&Driver->DeviceList);
    InitializeListHead(&Driver->IoPortList);
    InitializeListHead(&Driver->IoPacketQueue);
    InitializeListHead(&Driver->PendingIoPacketList);
    InitializeListHead(&Driver->ForwardedIrpList);
    InitializeListHead(&Driver->InterruptServiceList);
    KeInitializeEvent(&Driver->InitializationDoneEvent, NotificationEvent);
    KeInitializeEvent(&Driver->IoPacketQueuedEvent, SynchronizationEvent);

    PIO_FILE_OBJECT DriverFile = NULL;
    RET_ERR(ObReferenceObjectByName(DriverToLoad, OBJECT_TYPE_FILE, NULL,
				    (POBJECT *) &DriverFile));
    assert(DriverFile != NULL);
    Driver->DriverFile = DriverFile;

    /* Start the driver process */
    PPROCESS Process = NULL;
    RET_ERR(PsCreateProcess(DriverFile, Driver, NULL, &Process));
    assert(Process != NULL);
    Driver->DriverProcess = Process;

    /* Make sure we have loaded wdm.dll, even when the driver image does not
     * explicitly depend on it. */
    RET_ERR(PsLoadDll(Process, WDM_DLL_NAME));

    /* Get the init thread of driver process running */
    PTHREAD Thread = NULL;
    RET_ERR(PsCreateThread(Process, NULL, NULL, FALSE, &Thread));
    assert(Thread != NULL);
    Driver->MainEventLoopThread = Thread;

    /* Insert the driver object to the \Driver object directory. */
    RET_ERR(ObInsertObjectByName(DRIVER_OBJECT_DIRECTORY, Driver, DriverName));
    /* Add the driver to the list of all drivers */
    InsertTailList(&IopDriverList, &Driver->DriverLink);

    return STATUS_SUCCESS;
}

/*
 * The driver service registry key must already be loaded when this
 * routine is called.
 */
NTSTATUS IopLoadDriver(IN PCSTR DriverServicePath,
		       OUT OPTIONAL PIO_DRIVER_OBJECT *pDriverObject)
{
    /* Find the driver service basename, ie. "null" in
     * "\\Registry\\Machine\\CurrentControlSet\\Services\\null" */
    SIZE_T PathLen = strlen(DriverServicePath);
    /* Start from the last non-nul byte, look for the path separator '\\' */
    SIZE_T SepIndex = 0;
    for (SIZE_T i = PathLen-1; i > 0; i--) {
	if (DriverServicePath[i] == OBJ_NAME_PATH_SEPARATOR) {
	    SepIndex = i;
	    break;
	}
    }
    PCSTR DriverName = &DriverServicePath[SepIndex+1];
    /* DriverName must not be an empty string */
    if (*DriverName == '\0') {
	return STATUS_INVALID_PARAMETER;
    }

    /* Check \Driver object directory for all loaded drivers */
    MWORD BufLength = sizeof(DRIVER_OBJECT_DIRECTORY) + (PathLen - SepIndex) + 1;
    IopAllocateArray(DriverObjectPath, CHAR, BufLength);
    memcpy(DriverObjectPath, DRIVER_OBJECT_DIRECTORY, sizeof(DRIVER_OBJECT_DIRECTORY)-1);
    DriverObjectPath[sizeof(DRIVER_OBJECT_DIRECTORY)-1] = OBJ_NAME_PATH_SEPARATOR;
    memcpy(&DriverObjectPath[sizeof(DRIVER_OBJECT_DIRECTORY)], DriverName, PathLen - SepIndex);
    DriverObjectPath[BufLength-1] = '\0';
    DbgTrace("Object file %s driver name %s driver object %s\n",
	     DriverServicePath, DriverName, DriverObjectPath);
    PIO_DRIVER_OBJECT DriverObject = NULL;
    if (NT_SUCCESS(ObReferenceObjectByName(DriverObjectPath, OBJECT_TYPE_DRIVER, NULL,
					   (POBJECT *)&DriverObject))) {
	/* Driver is already loaded. We increase the reference count and return SUCCESS. */
	IopFreePool(DriverObjectPath);
	if (pDriverObject) {
	    *pDriverObject = DriverObject;
	}
	return STATUS_SUCCESS;
    }
    IopFreePool(DriverObjectPath);

    /* Read the ImagePath value from the driver service registry key.
     * The key must be loaded in memory at this point. */
    ULONG RegValueType;
    PCSTR DriverImagePath = NULL;
    POBJECT KeyObject = NULL;
    RET_ERR(CmReadKeyValueByPath(DriverServicePath, "ImagePath", &KeyObject,
				 &RegValueType, (PPVOID)&DriverImagePath));
    assert(KeyObject != NULL);
    if (RegValueType != REG_SZ && RegValueType != REG_EXPAND_SZ) {
	ObDereferenceObject(KeyObject);
	return STATUS_OBJECT_NAME_INVALID;
    }
    assert(DriverImagePath != NULL);

    /* Allocate the DriverObject */
    DRIVER_OBJ_CREATE_CONTEXT CreaCtx = {
	.DriverImagePath = DriverImagePath,
	.DriverServicePath = DriverServicePath,
	.DriverName = DriverName
    };
    RET_ERR(ObCreateObject(OBJECT_TYPE_DRIVER, (POBJECT *) &DriverObject, &CreaCtx));
    assert(DriverObject != NULL);
    ObDereferenceObject(KeyObject);

    if (pDriverObject) {
	*pDriverObject = DriverObject;
    }
    return STATUS_SUCCESS;
}

NTSTATUS NtLoadDriver(IN ASYNC_STATE State,
		      IN PTHREAD Thread,
		      IN PCSTR DriverServiceName)
{
    ASYNC_BEGIN(State, Locals, {
	    PIO_DRIVER_OBJECT DriverObject;
	});

    NTSTATUS Status = IopLoadDriver(DriverServiceName, &Locals.DriverObject);
    if (!NT_SUCCESS(Status)) {
	ASYNC_RETURN(State, Status);
    }
    assert(Locals.DriverObject != NULL);

    AWAIT(KeWaitForSingleObject, State, Locals, Thread,
	  &Locals.DriverObject->InitializationDoneEvent.Header, FALSE);

    /* If the driver initialization failed, inform the caller of the error status */
    if (Locals.DriverObject->MainEventLoopThread == NULL) {
	ASYNC_RETURN(State, STATUS_UNSUCCESSFUL);
    }
    if (!NT_SUCCESS(Locals.DriverObject->MainEventLoopThread->ExitStatus)) {
	ASYNC_RETURN(State, Locals.DriverObject->MainEventLoopThread->ExitStatus);
    }

    ASYNC_END(State, STATUS_SUCCESS);
}

NTSTATUS IopEnableX86Port(IN ASYNC_STATE AsyncState,
                          IN PTHREAD Thread,
                          IN USHORT PortNum,
                          OUT MWORD *Cap)
{
    assert(Thread != NULL);
    assert(Cap != NULL);
    PPROCESS Process = Thread->Process;
    assert(Process != NULL);
    PIO_DRIVER_OBJECT DriverObject = Process->DriverObject;
    assert(DriverObject != NULL);

    IopAllocatePool(IoPort, X86_IOPORT);
    RET_ERR_EX(KeEnableIoPortEx(Process->CSpace, PortNum, IoPort),
	       IopFreePool(IoPort));
    InsertTailList(&DriverObject->IoPortList, &IoPort->Link);
    *Cap = IoPort->TreeNode.Cap;
    return STATUS_SUCCESS;
}

static NTSTATUS IopCreateInterruptServiceThread(IN PIO_DRIVER_OBJECT DriverObject,
						IN ULONG Vector,
						IN PIO_INTERRUPT_SERVICE_THREAD_ENTRY EntryPoint,
						IN PVOID ClientSideContext,
						OUT PINTERRUPT_SERVICE *pSvc)
{
    assert(DriverObject != NULL);
    assert(DriverObject->DriverProcess != NULL);
    assert(pSvc != NULL);
    NTSTATUS Status = STATUS_NTOS_BUG;
    IopAllocatePool(Svc, INTERRUPT_SERVICE);

    /* Create a notification for client side to use as the interrupt notification */
    IF_ERR_GOTO(out, Status,
		KeCreateNotificationEx(&Svc->Notification,
				       DriverObject->DriverProcess->CSpace));

    CONTEXT Context;
    memset(&Context, 0, sizeof(CONTEXT));
    KeSetThreadContextFromEntryPoint(&Context, EntryPoint, ClientSideContext);

    /* Also create the mutex object (which is simply a notification) for the
     * client side to synchronize data access between ISR and the rest of the driver. */
    IF_ERR_GOTO(out, Status,
		KeCreateNotificationEx(&Svc->InterruptMutex,
				       DriverObject->DriverProcess->CSpace));

    IF_ERR_GOTO(out, Status,
		PsCreateThread(DriverObject->DriverProcess, &Context, NULL,
			       TRUE, &Svc->IsrThread));
    assert(Svc->IsrThread != NULL);
    MmInitializeCapTreeNode(&Svc->IsrThreadClientCap, CAP_TREE_NODE_TCB,
			    0, DriverObject->DriverProcess->CSpace, NULL);
    IF_ERR_GOTO(out, Status,
		PsSetThreadPriority(Svc->IsrThread, DEVICE_INTERRUPT_MIN_LEVEL + Vector));
    IF_ERR_GOTO(out, Status,
		MmCapTreeCopyNode(&Svc->IsrThreadClientCap,
				  &Svc->IsrThread->TreeNode,
				  seL4_AllRights));
    InsertTailList(&DriverObject->InterruptServiceList, &Svc->Link);

    /* Connect the given interrupt vector to the interrupt thread */
    IF_ERR_GOTO(out, Status,
		KeCreateIrqHandlerEx(&Svc->IrqHandler, Vector,
				     Svc->IsrThread->Process->CSpace));
    Svc->Vector = Vector;

    *pSvc = Svc;
    return STATUS_SUCCESS;

out:
    if (Svc != NULL) {
	if (Svc->IsrThreadClientCap.Cap != 0) {
	    MmCapTreeDeleteNode(&Svc->IsrThreadClientCap);
	}
	if (Svc->IsrThread != NULL) {
	    ObDereferenceObject(Svc->IsrThread);
	}
	if (Svc->Notification.TreeNode.Cap != 0) {
	    KeDeleteNotification(&Svc->Notification);
	}
	if (Svc->InterruptMutex.TreeNode.Cap != 0) {
	    KeDeleteNotification(&Svc->InterruptMutex);
	}
	IopFreePool(Svc);
    }
    return Status;
}

NTSTATUS IopConnectInterrupt(IN ASYNC_STATE AsyncState,
			     IN PTHREAD Thread,
			     IN ULONG Vector,
			     IN BOOLEAN ShareVector,
			     IN PIO_INTERRUPT_SERVICE_THREAD_ENTRY EntryPoint,
			     IN PVOID ClientSideContext, /* Context as in EntryPoint(Context) */
			     OUT MWORD *WdmServiceCap,
			     OUT MWORD *ThreadCap,
			     OUT PVOID *ThreadIpcBuffer,
			     OUT MWORD *IrqHandler,
			     OUT MWORD *InterruptNotification,
			     OUT MWORD *InterruptMutex)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    assert(Thread->Process->DriverObject != NULL);
    if (ShareVector) {
	UNIMPLEMENTED;
    }

    /* Create the interrupt service thread, together with the interrupt notification
     * and interrupt mutex object */
    PINTERRUPT_SERVICE Svc = NULL;
    RET_ERR(IopCreateInterruptServiceThread(Thread->Process->DriverObject, Vector,
					    EntryPoint, ClientSideContext, &Svc));
    assert(Svc != NULL);

    *WdmServiceCap = Svc->IsrThread->WdmServiceEndpoint->TreeNode.Cap;
    *ThreadCap = Svc->IsrThreadClientCap.Cap;
    *ThreadIpcBuffer = (PVOID)Svc->IsrThread->IpcBufferClientAddr;
    *IrqHandler = Svc->IrqHandler.TreeNode.Cap;
    *InterruptNotification = Svc->Notification.TreeNode.Cap;
    *InterruptMutex = Svc->InterruptMutex.TreeNode.Cap;
    return STATUS_SUCCESS;
}

NTSTATUS IopCreateCoroutineStack(IN ASYNC_STATE State,
				 IN PTHREAD Thread,
				 OUT PVOID *pStackTop)
{
    assert(Thread->Process != NULL);
    assert(Thread->Process->DriverObject != NULL);
    return PsMapDriverCoroutineStack(Thread->Process,
				     (MWORD *)pStackTop);
}

NTSTATUS IopNotifyMainThread(IN ASYNC_STATE State,
			     IN PTHREAD Thread)
{
    assert(Thread->Process != NULL);
    assert(Thread->Process->DriverObject != NULL);
    /* Signal the driver to check for DPC queue and IO work item queue */
    KeSetEvent(&Thread->Process->DriverObject->IoPacketQueuedEvent);
    return STATUS_SUCCESS;
}
