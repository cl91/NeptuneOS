#include "iop.h"

/*
 * Creation context for the driver object creation routine
 */
typedef struct _DRIVER_OBJ_CREATE_CONTEXT {
    PCSTR DriverImagePath;
    PCSTR DriverServicePath;
    PSECTION ImageSection;
} DRIVER_OBJ_CREATE_CONTEXT, *PDRIVER_OBJ_CREATE_CONTEXT;

NTSTATUS IopDriverObjectCreateProc(IN POBJECT Object,
				   IN PVOID CreaCtx)
{
    PIO_DRIVER_OBJECT Driver = (PIO_DRIVER_OBJECT)Object;
    PDRIVER_OBJ_CREATE_CONTEXT Ctx = (PDRIVER_OBJ_CREATE_CONTEXT)CreaCtx;
    assert(Ctx->ImageSection);
    PCSTR DriverToLoad = Ctx->DriverImagePath;
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

    /* Start the driver process */
    PPROCESS Process = NULL;
    RET_ERR(PsCreateProcess(Ctx->ImageSection, Driver, &Process));
    assert(Process != NULL);
    Driver->DriverProcess = Process;

    /* Get the init thread of driver process running */
    PTHREAD Thread = NULL;
    RET_ERR(PsCreateThread(Process, NULL, NULL, FALSE, &Thread));
    assert(Thread != NULL);
    Driver->MainEventLoopThread = Thread;

    /* Add the driver to the list of all drivers */
    InsertTailList(&IopDriverList, &Driver->DriverLink);

    return STATUS_SUCCESS;
}

VOID IopDriverObjectDeleteProc(IN POBJECT Self)
{
    /* TODO */
}

NTSTATUS IopLoadDriver(IN ASYNC_STATE State,
		       IN PTHREAD Thread,
		       IN PCSTR DriverServicePath,
		       OUT OPTIONAL PIO_DRIVER_OBJECT *pDriverObject)
{
    NTSTATUS Status;
    ULONG RegValueType = 0;
    PCSTR DriverImagePath = NULL;
    POBJECT KeyObject = NULL;
    PIO_FILE_OBJECT DriverImageFile = NULL;
    PSECTION DriverImageSection = NULL;

    ASYNC_BEGIN(State, Locals, {
	    POBJECT DriverObjectDirectory;
	    PCSTR DriverName;
	    PCSTR DriverImagePath;
	    POBJECT KeyObject;
	    OB_OBJECT_ATTRIBUTES ObjectAttributes;
	    IO_OPEN_CONTEXT OpenContext;
	    PIO_FILE_OBJECT DriverImageFile;
	    PSECTION DriverImageSection;
	});

    /* Get the object directory for all driver objects. Note on Windows
     * and ReactOS, device driver objects are placed under \Driver while
     * file system drivers are placed under \FileSystem. We do not make
     * this distinction on Neptune OS and place both under \Driver. */
    ASYNC_RET_ERR(State, ObReferenceObjectByName(DRIVER_OBJECT_DIRECTORY,
						 OBJECT_TYPE_DIRECTORY,
						 FALSE, NULL,
						 &Locals.DriverObjectDirectory));
    assert(Locals.DriverObjectDirectory);

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
    Locals.DriverName = &DriverServicePath[SepIndex+1];
    /* DriverName must not be an empty string */
    if (*Locals.DriverName == '\0') {
	ASYNC_RETURN(State, STATUS_INVALID_PARAMETER);
    }

    /* Check the \Driver object directory to see if the driver has already
     * been loaded. If it is, just return the existing driver object. */
    PIO_DRIVER_OBJECT DriverObject = NULL;
    Status = ObReferenceObjectByName(Locals.DriverName, OBJECT_TYPE_DRIVER,
				     Locals.DriverObjectDirectory, FALSE,
				     (POBJECT *)&DriverObject);
    if (NT_SUCCESS(Status)) {
	assert(DriverObject);
	/* Loading an already loaded driver does NOT increase its reference
	 * count, so decrease the reference count increased by the call above. */
	ObDereferenceObject(DriverObject);
	if (pDriverObject) {
	    *pDriverObject = DriverObject;
	}
	ASYNC_RETURN(State, STATUS_SUCCESS);
    }

    /* Read the ImagePath value from the driver service registry key. */
    AWAIT_EX(Status, CmReadKeyValueByPath, State, Locals, Thread,
	     DriverServicePath, "ImagePath", &KeyObject,
	     &RegValueType, (PPVOID)&DriverImagePath);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }
    assert(KeyObject);
    assert(DriverImagePath);
    Locals.KeyObject = KeyObject;
    Locals.DriverImagePath = DriverImagePath;

    if (RegValueType != REG_SZ && RegValueType != REG_EXPAND_SZ) {
	Status = STATUS_OBJECT_NAME_INVALID;
	goto out;
    }
    assert(Locals.DriverImagePath);

    /* Open the driver image file */
    Locals.ObjectAttributes.Attributes = OBJ_CASE_INSENSITIVE;
    Locals.ObjectAttributes.ObjectNameBuffer = Locals.DriverImagePath;
    Locals.ObjectAttributes.ObjectNameBufferLength = strlen(Locals.DriverImagePath) + 1;
    Locals.OpenContext.Header.Type = OPEN_CONTEXT_DEVICE_OPEN;
    Locals.OpenContext.OpenPacket.CreateFileType = CreateFileTypeNone;
    Locals.OpenContext.OpenPacket.CreateOptions = FILE_SYNCHRONOUS_IO_NONALERT
	| FILE_NON_DIRECTORY_FILE;
    Locals.OpenContext.OpenPacket.FileAttributes = 0;
    Locals.OpenContext.OpenPacket.ShareAccess = FILE_SHARE_DELETE | FILE_SHARE_READ;
    Locals.OpenContext.OpenPacket.Disposition = 0;

    AWAIT_EX(Status, ObOpenObjectByNameEx, State, Locals,
	     Thread, Locals.ObjectAttributes, OBJECT_TYPE_FILE, FILE_EXECUTE,
	     (POB_OPEN_CONTEXT)&Locals.OpenContext, FALSE, (PVOID *)&DriverImageFile);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }
    Locals.DriverImageFile = DriverImageFile;

    /* Create the driver image section */
    AWAIT_EX(Status, MmCreateSectionEx, State, Locals, Thread,
	     Locals.DriverImageFile, PAGE_EXECUTE, SEC_IMAGE, &DriverImageSection);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }
    Locals.DriverImageSection = DriverImageSection;

    /* Create the driver object */
    DRIVER_OBJ_CREATE_CONTEXT CreaCtx = {
	.DriverImagePath = Locals.DriverImagePath,
	.DriverServicePath = DriverServicePath,
	.ImageSection = Locals.DriverImageSection
    };
    PIO_DRIVER_OBJECT DriverObject = NULL;
    Status = ObCreateObject(OBJECT_TYPE_DRIVER, (POBJECT *)&DriverObject, &CreaCtx);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }
    Status = ObInsertObject(Locals.DriverObjectDirectory, DriverObject,
			    Locals.DriverName, 0);
    if (!NT_SUCCESS(Status)) {
	/* This insertion may fail since another process might have attempted to
	 * load the same driver concurrently. In this case we should delete the
	 * driver object that we just created. */
	ObDereferenceObject(DriverObject);
	goto out;
    }
    if (pDriverObject) {
	*pDriverObject = DriverObject;
    }

out:
    /* Regardless of success or error, we need to dereference the objects
     * referenced above. */
    if (Locals.DriverObjectDirectory) {
	ObDereferenceObject(Locals.DriverObjectDirectory);
    }
    if (Locals.KeyObject) {
	ObDereferenceObject(Locals.KeyObject);
    }
    if (Locals.DriverImageSection) {
	ObDereferenceObject(Locals.DriverImageSection);
    }
    if (Locals.DriverImageFile) {
	ObDereferenceObject(Locals.DriverImageFile);
    }
    ASYNC_END(State, Status);
}

NTSTATUS NtLoadDriver(IN ASYNC_STATE State,
		      IN PTHREAD Thread,
		      IN PCSTR DriverServiceName)
{
    PIO_DRIVER_OBJECT DriverObject = NULL;
    NTSTATUS Status;

    ASYNC_BEGIN(State, Locals, {
	    PIO_DRIVER_OBJECT DriverObject;
	});

    AWAIT_EX(Status, IopLoadDriver, State, Locals, Thread,
	     DriverServiceName, &DriverObject);
    if (!NT_SUCCESS(Status)) {
	ASYNC_RETURN(State, Status);
    }
    assert(DriverObject != NULL);
    Locals.DriverObject = DriverObject;

    AWAIT(KeWaitForSingleObject, State, Locals, Thread,
	  &Locals.DriverObject->InitializationDoneEvent.Header, FALSE, NULL);

    /* If the driver initialization failed, inform the caller of the error status.
     * Otherwise return success (in case of success, MainEventLoopThread->ExitStatus
     * will contain STATUS_SUCCESS). */
    if (Locals.DriverObject->MainEventLoopThread) {
	Status = Locals.DriverObject->MainEventLoopThread->ExitStatus;
    } else {
	Status = STATUS_UNSUCCESSFUL;
    }
    if (!NT_SUCCESS(Status)) {
	ObDereferenceObject(Locals.DriverObject);
    }

    ASYNC_END(State, Status);
}

NTSTATUS WdmEnableX86Port(IN ASYNC_STATE AsyncState,
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

NTSTATUS WdmConnectInterrupt(IN ASYNC_STATE AsyncState,
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

NTSTATUS WdmCreateCoroutineStack(IN ASYNC_STATE State,
				 IN PTHREAD Thread,
				 OUT PVOID *pStackTop)
{
    assert(Thread->Process != NULL);
    assert(Thread->Process->DriverObject != NULL);
    return PsMapDriverCoroutineStack(Thread->Process,
				     (MWORD *)pStackTop);
}

NTSTATUS WdmNotifyMainThread(IN ASYNC_STATE State,
			     IN PTHREAD Thread)
{
    assert(Thread->Process != NULL);
    assert(Thread->Process->DriverObject != NULL);
    /* Signal the driver to check for DPC queue and IO work item queue */
    KeSetEvent(&Thread->Process->DriverObject->IoPacketQueuedEvent);
    return STATUS_SUCCESS;
}
