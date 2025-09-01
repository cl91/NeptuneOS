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
    InitializeListHead(&Driver->IoTimerList);
    InitializeListHead(&Driver->IoPacketQueue);
    InitializeListHead(&Driver->PendingIoPacketList);
    InitializeListHead(&Driver->ForwardedIrpList);
    InitializeListHead(&Driver->CloseDeviceMsgList);
    InitializeListHead(&Driver->InterruptServiceList);
    KeInitializeEvent(&Driver->InitializationDoneEvent, NotificationEvent);
    KeInitializeEvent(&Driver->IoPacketQueuedEvent, SynchronizationEvent);

    /* Start the driver process */
    PPROCESS Process = NULL;
    RET_ERR(PsCreateProcess(Ctx->ImageSection, Driver, &Process));
    assert(Process != NULL);
    Driver->DriverProcess = Process;
    ObpReferenceObject(Process);

    /* Get the init thread of driver process running */
    PTHREAD Thread = NULL;
    RET_ERR(PsCreateThread(Process, NULL, NULL, 0, &Thread));
    assert(Thread != NULL);
    Driver->MainEventLoopThread = Thread;
    ObpReferenceObject(Thread);

    /* Add the driver to the list of all drivers */
    InsertTailList(&IopDriverList, &Driver->DriverLink);

    return STATUS_SUCCESS;
}

VOID IopDriverObjectDeleteProc(IN POBJECT Self)
{
    PIO_DRIVER_OBJECT Driver = Self;

    /* Since creating a device object increases the refcount of its driver
     * object, if we get here the device list should be empty. */
    assert(IsListEmpty(&Driver->DeviceList));

    /* Delete the CloseDevice message that we queued in IopGrantDeviceHandleToDriver.
     * Note the device objects in the CloseDevice message list are all foreign device
     * objects (those that are not created by this driver). */
    LoopOverList(Msg, &Driver->CloseDeviceMsgList, CLOSE_DEVICE_MESSAGE, DriverLink) {
	assert(Msg->DeviceObject->DriverObject != Driver);
	RemoveEntryList(&Msg->DeviceLink);
	RemoveEntryList(&Msg->DriverLink);
	ObDereferenceObject(Msg->DeviceObject);
	IopFreePool(Msg->Msg);
	IopFreePool(Msg);
    }

    /* Delete all IO packets in PendingIoPacketList and IoPacketQueue. Since all queued
     * IO requests have been taken care of in IopUnloadDriver, the only IO packets remaining
     * are message packets. */
    LoopOverList(Irp, &Driver->PendingIoPacketList, IO_PACKET, IoPacketLink) {
	assert(Irp->Type != IoPacketTypeRequest);
	RemoveEntryList(&Irp->IoPacketLink);
	IopFreePool(Irp);
    }
    LoopOverList(Irp, &Driver->IoPacketQueue, IO_PACKET, IoPacketLink) {
	assert(Irp->Type != IoPacketTypeRequest);
	RemoveEntryList(&Irp->IoPacketLink);
	IopFreePool(Irp);
    }

    /* If the driver has registered IO timer, delete them. */
    LoopOverList(IoTimer, &Driver->IoTimerList, IO_TIMER, DriverLink) {
	KeRemoveIoTimerFromQueue(IoTimer);
	RemoveEntryList(&IoTimer->DriverLink);
	IopFreePool(IoTimer);
    }

    if (Driver->MainEventLoopThread) {
	ObDereferenceObject(Driver->MainEventLoopThread);
    }
    if (Driver->DriverProcess) {
	ObDereferenceObject(Driver->DriverProcess);
	/* After dereferencing the DriverProcess might have become NULL.
	 * This can happen if the driver process has crashed. In the case
	 * it is not NULL, we set its DriverObject to NULL so the delete
	 * routine of the PROCESS object will not try to access the driver
	 * object being deleted. */
	if (Driver->DriverProcess) {
	    Driver->DriverProcess->DriverObject = NULL;
	}
    }
    if (Driver->DriverImagePath) {
	IopFreePool(Driver->DriverImagePath);
    }
    if (Driver->DriverRegistryPath) {
	IopFreePool(Driver->DriverRegistryPath);
    }
    /* TODO: Close IO ports, disconnect interrupts, uninit cache. */
    KeUninitializeEvent(&Driver->InitializationDoneEvent);
    KeUninitializeEvent(&Driver->IoPacketQueuedEvent);
    RemoveEntryList(&Driver->DriverLink);
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
	    PIO_DRIVER_OBJECT DriverObject;
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
    /* Starting from the last non-nul byte, look for the path separator '\\' */
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

    /* Now wait on the InitializationDoneEvent for the main event loop of the
     * driver process to start. */
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
    } else if (pDriverObject) {
	Locals.DriverObject->DriverLoaded = TRUE;
	*pDriverObject = Locals.DriverObject;
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

NTSTATUS IoUnloadDriver(IN ASYNC_STATE State,
			IN PTHREAD Thread,
			IN PIO_DRIVER_OBJECT DriverObject,
			IN BOOLEAN NormalExit,
			IN NTSTATUS ExitStatus)
{
    NTSTATUS Status;
    ASYNC_BEGIN(State);

    DbgTrace("Unloading driver %p (%s)\n", DriverObject,
	     KEDBG_PROCESS_TO_FILENAME(DriverObject->DriverProcess));

    if (NormalExit) {
	assert(FALSE);
	ASYNC_RETURN(State, STATUS_NOT_IMPLEMENTED);
    }

    /* Move all IO packets in PendingIoPacketList back to the driver's IoPacketQueue. */
    LoopOverList(Irp, &DriverObject->PendingIoPacketList, IO_PACKET, IoPacketLink) {
	RemoveEntryList(&Irp->IoPacketLink);
	InsertTailList(&DriverObject->IoPacketQueue, &Irp->IoPacketLink);
    }

    /* For each IO request packet queued to this driver, complete the IRP with error. */
    LoopOverList(Irp, &DriverObject->IoPacketQueue, IO_PACKET, IoPacketLink) {
	if (Irp->Type != IoPacketTypeRequest) {
	    continue;
	}
	RemoveEntryList(&Irp->IoPacketLink);
	InitializeListHead(&Irp->IoPacketLink);
	PPENDING_IRP PendingIrp = IopLocateIrpInOriginalRequestor(Irp->Request.OriginalRequestor,
								  Irp);
	if (!PendingIrp) {
	    /* If the PENDING_IRP is invalid, we must have a bug somewhere, so assert
	     * in debug build and try to continue in release build. */
	    assert(FALSE);
	    IopFreePool(Irp);
	    continue;
	}
	/* If an IO packet is in the driver's IO packet queue, the PENDING_IRP we need to
	 * complete is always the lowest-level PENDING_IRP, so locate that now. */
	while (PendingIrp->ForwardedTo != NULL) {
	    PendingIrp = PendingIrp->ForwardedTo;
	}
	IO_STATUS_BLOCK IoStatus = { .Status = STATUS_DRIVER_PROCESS_TERMINATED };
	IopCompletePendingIrp(PendingIrp, IoStatus, NULL, 0);
    }

    /* In the case of a driver forwarding an IRP to another driver, since we do not allow
     * a driver to forward an IRP to itself (the client-side routines will process such an
     * IRP locally), calling IopCompletePendingIrp will only detach IO packets from the IO
     * packet queue and never add them back, so at the end of the previous loop, the IO packet
     * queue will no longer contain any IO requests (only server messages will remain). */
    LoopOverList(Irp, &DriverObject->IoPacketQueue, IO_PACKET, IoPacketLink) {
	assert(Irp->Type != IoPacketTypeRequest);
    }

    /* Cancel all pending IRPs that this driver has requested. */
    LoopOverList(PendingIrp, &DriverObject->ForwardedIrpList, PENDING_IRP, Link) {
	IopCancelPendingIrp(PendingIrp);
    }

    /* Forcibly remove all device objects that this driver has created. */
    LoopOverList(DevObj, &DriverObject->DeviceList, IO_DEVICE_OBJECT, DeviceLink) {
	IopForceRemoveDevice(DevObj);
    }

    /* At this point the driver object may still have more than one references
     * if one of its device objects is being opened. Dereference the driver object so
     * when the open routine returns an error status, the device object(s) and the
     * driver object itself will be deleted. */
    ObDereferenceObject(DriverObject);

    Status = STATUS_SUCCESS;
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

    ASYNC_END(State, Status);
}

NTSTATUS WdmEnableX86Port(IN ASYNC_STATE AsyncState,
                          IN PTHREAD Thread,
                          IN USHORT PortNum,
			  IN USHORT Count,
                          OUT MWORD *Cap)
{
#if defined(_M_IX86) || defined(_M_AMD64)
    assert(Thread != NULL);
    assert(Cap != NULL);
    PPROCESS Process = Thread->Process;
    assert(Process != NULL);
    PIO_DRIVER_OBJECT DriverObject = Process->DriverObject;
    assert(DriverObject != NULL);

    IopAllocatePool(IoPort, X86_IOPORT);
    RET_ERR_EX(KeEnableIoPortEx(Process->SharedCNode, PortNum, Count, IoPort),
	       IopFreePool(IoPort));
    InsertTailList(&DriverObject->IoPortList, &IoPort->Link);
    *Cap = IoPort->TreeNode.Cap;
    return STATUS_SUCCESS;
#else
    return STATUS_NOT_SUPPORTED;
#endif
}

static NTSTATUS IopCreateInterruptServiceThread(IN PTHREAD DriverThread,
						IN ULONG Vector,
						IN PIO_INTERRUPT_SERVICE_THREAD_ENTRY EntryPoint,
						IN PVOID ClientSideContext,
						OUT PINTERRUPT_SERVICE *pSvc)
{
    PPROCESS DriverProcess = DriverThread->Process;
    assert(DriverProcess != NULL);
    PIO_DRIVER_OBJECT DriverObject = DriverProcess->DriverObject;
    assert(DriverObject != NULL);
    assert(DriverObject->DriverProcess == DriverProcess);
    assert(pSvc != NULL);
    NTSTATUS Status = STATUS_NTOS_BUG;
    IopAllocatePool(Svc, INTERRUPT_SERVICE);

    CONTEXT Context;
    memset(&Context, 0, sizeof(CONTEXT));
    KeSetThreadContextFromEntryPoint(&Context, EntryPoint, ClientSideContext);

    /* Create the driver ISR thread and copy its thread cap into the CSpace of the
     * calling thread, which will usually be the driver's main event loop thread. */
    IF_ERR_GOTO(err, Status,
		PsCreateThread(DriverProcess, &Context, NULL,
			       PS_CREATE_ISR_THREAD | PS_CREATE_THREAD_SUSPENDED,
			       &Svc->IsrThread));
    assert(Svc->IsrThread != NULL);
    IF_ERR_GOTO(err, Status,
		PsSetThreadPriority(Svc->IsrThread, DEVICE_INTERRUPT_MIN_LEVEL + Vector));

    /* Create a notification for driver ISR thread to use as the interrupt notification */
    IF_ERR_GOTO(err, Status,
		KeCreateNotificationEx(&Svc->Notification,
				       Svc->IsrThread->CSpace));

    /* Also create the mutex object (which is simply a notification) for the
     * client side to synchronize data access between ISR and the rest of the driver. */
    IF_ERR_GOTO(err, Status,
		KeCreateNotificationEx(&Svc->InterruptMutex, DriverProcess->SharedCNode));

    /* Connect the given interrupt vector to the interrupt thread */
    IF_ERR_GOTO(err, Status,
		KeCreateIrqHandlerEx(&Svc->IrqHandler, Vector,
				     Svc->IsrThread->CSpace));

    /* Assign a handle for the ISR thread in the driver process */
    IF_ERR_GOTO(err, Status, ObCreateHandle(DriverProcess, Svc->IsrThread, FALSE,
					    &Svc->ThreadHandle));

    Svc->Vector = Vector;
    InsertTailList(&DriverObject->InterruptServiceList, &Svc->Link);
    *pSvc = Svc;
    return STATUS_SUCCESS;

err:
    if (Svc != NULL) {
	assert(!Svc->ThreadHandle);
	if (Svc->Notification.TreeNode.Cap != 0) {
	    KeDestroyNotification(&Svc->Notification);
	}
	if (Svc->InterruptMutex.TreeNode.Cap != 0) {
	    KeDestroyNotification(&Svc->InterruptMutex);
	}
	if (Svc->IsrThread != NULL) {
	    ObDereferenceObject(Svc->IsrThread);
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
			     OUT HANDLE *ThreadHandle,
			     OUT MWORD *IrqHandler,
			     OUT MWORD *InterruptNotification,
			     OUT MWORD *InterruptMutex)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    assert(Thread->Process->DriverObject != NULL);
    assert(Thread == Thread->Process->DriverObject->MainEventLoopThread);
    if (ShareVector) {
	DbgTrace("WARNING: Interrupt sharing is disallowed.\n");
    }
    /* Check if the interrupt level has been connected. */
    if (IopIsInterruptVectorAssigned(Thread->Process->DriverObject, Vector)) {
	return STATUS_ACCESS_DENIED;
    }

    /* Create the interrupt service thread, together with the interrupt notification
     * and interrupt mutex object */
    PINTERRUPT_SERVICE Svc = NULL;
    RET_ERR(IopCreateInterruptServiceThread(Thread, Vector,
					    EntryPoint, ClientSideContext, &Svc));
    assert(Svc != NULL);

    *ThreadHandle = Svc->ThreadHandle;
    *IrqHandler = PsThreadCNodeIndexToGuardedCap(Svc->IrqHandler.TreeNode.Cap,
						 Svc->IsrThread);
    *InterruptNotification = PsThreadCNodeIndexToGuardedCap(Svc->Notification.TreeNode.Cap,
							    Svc->IsrThread);
    *InterruptMutex = Svc->InterruptMutex.TreeNode.Cap;
    return STATUS_SUCCESS;
}

NTSTATUS WdmCreateDpcThread(IN ASYNC_STATE AsyncState,
			    IN PTHREAD Thread,
			    IN PVOID EntryPoint,
			    OUT HANDLE *ThreadHandle,
			    OUT MWORD *WdmServiceCap,
			    OUT MWORD *DpcNotificationCap)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    PIO_DRIVER_OBJECT DriverObject = Thread->Process->DriverObject;
    assert(DriverObject != NULL);
    assert(Thread == DriverObject->MainEventLoopThread);

    CONTEXT Context;
    memset(&Context, 0, sizeof(CONTEXT));
    KeSetThreadContextFromEntryPoint(&Context, EntryPoint, NULL);

    NTSTATUS Status = PsCreateThread(Thread->Process, &Context, NULL,
				     PS_CREATE_THREAD_SUSPENDED,
				     &DriverObject->DpcThread);
    if (!NT_SUCCESS(Status)) {
	goto err;
    }
    assert(DriverObject->DpcThread != NULL);
    IF_ERR_GOTO(err, Status,
		PsSetThreadPriority(DriverObject->DpcThread, DISPATCH_LEVEL));

    /* Create a notification for DPC thread to synchronize access with the main thread */
    IF_ERR_GOTO(err, Status,
		KeCreateNotificationEx(&DriverObject->DpcNotification,
				       Thread->Process->SharedCNode));
    assert(DriverObject->DpcNotification.TreeNode.Cap);

    /* Derive the notification cap in the server CSpace so we can signal for timer
     * expiration. The cap has a badge indicating its purpose. */
    extern CNODE MiNtosCNode;
    DriverObject->TimerNotification.CNode = &MiNtosCNode;
    IF_ERR_GOTO(err, Status,
		MmCapTreeDeriveBadgedNode(&DriverObject->TimerNotification,
					  &DriverObject->DpcNotification.TreeNode,
					  seL4_AllRights, TIMER_NOTIFICATION_BADGE));

    /* Assign a handle for the DPC thread in the driver process */
    IF_ERR_GOTO(err, Status, ObCreateHandle(Thread->Process, DriverObject->DpcThread,
					    FALSE, ThreadHandle));
    *WdmServiceCap =
	PsThreadCNodeIndexToGuardedCap(DriverObject->DpcThread->WdmServiceEndpoint->TreeNode.Cap,
				       DriverObject->DpcThread);
    *DpcNotificationCap = DriverObject->DpcNotification.TreeNode.Cap;
    return STATUS_SUCCESS;

err:
    if (DriverObject->DpcThread) {
	ObDereferenceObject(DriverObject->DpcThread);
    }
    if (DriverObject->TimerNotification.Cap) {
	MmCapTreeDeleteNode(&DriverObject->TimerNotification);
    }
    if (DriverObject->DpcNotification.TreeNode.Cap) {
	KeDestroyNotification(&DriverObject->DpcNotification);
    }
    return Status;
}

NTSTATUS WdmCreateTimer(IN ASYNC_STATE State,
			IN PTHREAD Thread,
			OUT GLOBAL_HANDLE *GlobalHandle)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    PIO_DRIVER_OBJECT DriverObject = Thread->Process->DriverObject;
    assert(DriverObject);
    IopAllocatePool(IoTimer, IO_TIMER);
    IoTimer->DriverObject = DriverObject;
    InsertHeadList(&DriverObject->IoTimerList, &IoTimer->DriverLink);
    *GlobalHandle = OBJECT_TO_GLOBAL_HANDLE(IoTimer);
    return STATUS_SUCCESS;
}

NTSTATUS WdmSetTimer(IN ASYNC_STATE State,
		     IN PTHREAD Thread,
		     IN GLOBAL_HANDLE GlobalHandle,
		     IN PULARGE_INTEGER AbsoluteDueTime,
		     IN LONG Period)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    PIO_DRIVER_OBJECT DriverObject = Thread->Process->DriverObject;
    assert(DriverObject);
    LoopOverList(IoTimer, &DriverObject->IoTimerList, IO_TIMER, DriverLink) {
	if (OBJECT_TO_GLOBAL_HANDLE(IoTimer) == GlobalHandle) {
	    KeQueueIoTimer(IoTimer, *AbsoluteDueTime, Period);
	    return STATUS_SUCCESS;
	}
    }
    return STATUS_INVALID_HANDLE;
}

NTSTATUS WdmCreateCoroutineStack(IN ASYNC_STATE State,
				 IN PTHREAD Thread,
				 OUT PVOID *pStackTop)
{
    assert(Thread->Process != NULL);
    assert(Thread->Process->DriverObject != NULL);
    assert(Thread == Thread->Process->DriverObject->MainEventLoopThread);
    return PsMapDriverCoroutineStack(Thread->Process, (MWORD *)pStackTop);
}

NTSTATUS WdmNotifyMainThread(IN ASYNC_STATE State,
			     IN PTHREAD Thread)
{
    assert(Thread->Process != NULL);
    assert(Thread->Process->DriverObject != NULL);
    assert(Thread != Thread->Process->DriverObject->MainEventLoopThread);
    assert(Thread == Thread->Process->DriverObject->DpcThread);
    /* Signal the driver to check for DPC queue and IO work item queue */
    KeSetEvent(&Thread->Process->DriverObject->IoPacketQueuedEvent);
    return STATUS_SUCCESS;
}
