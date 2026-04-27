#include "iop.h"

LIST_ENTRY IoBugcheckNotificationList;

PIO_DRIVER_OBJECT IoGetDriverObjectFromProcess(IN PPROCESS Process)
{
    return AVL_NODE_TO_DRIVER_OBJECT(AvlTreeFindNode(&IopDriverObjectTree,
						     (ULONG_PTR)Process));
}

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
    InitializeListHead(&Driver->CloseDeviceMsgList);
    InitializeListHead(&Driver->InterruptServiceList);
    InitializeListHead(&Driver->PlugPlayNotificationList);
    KeInitializeEvent(&Driver->InitializationDoneEvent, NotificationEvent);
    IopAssignSignalGroupForDriver(Driver);

    /* Start the driver process */
    PPROCESS Process = NULL;
    RET_ERR(PsCreateProcess(Ctx->ImageSection, Driver, &Process));
    assert(Process != NULL);
    PAVL_NODE Parent = AvlTreeFindNodeOrParent(&IopDriverObjectTree, (ULONG_PTR)Process);
    if (Parent && Parent->Key == (ULONG_PTR)Process) {
	assert(FALSE);
	ObDereferenceObject(Process);
	return STATUS_ALREADY_INITIALIZED;
    }
    Driver->Node.Key = (ULONG_PTR)Process;
    AvlTreeInsertNode(&IopDriverObjectTree, Parent, &Driver->Node);
    ObReferenceObjectByPointer(Process);

    RET_ERR(KeCreateNotificationEx(&Driver->DpcMutex, Process->SharedCNode));
    Process->InitInfo.DriverInitInfo.DpcMutexCap = Driver->DpcMutex.TreeNode.Cap;
    RET_ERR(KeCreateNotificationEx(&Driver->WorkItemMutex, Process->SharedCNode));
    Process->InitInfo.DriverInitInfo.WorkItemMutexCap = Driver->WorkItemMutex.TreeNode.Cap;
#if defined(_M_IX86) || defined(_M_AMD64)
    RET_ERR(KeCreateNotificationEx(&Driver->X86PortMutex, Process->SharedCNode));
    Process->InitInfo.DriverInitInfo.X86PortMutexCap = Driver->X86PortMutex.TreeNode.Cap;
#endif

    /* Create the init thread of driver process, which is the event loop thread. */
    PTHREAD Thread = NULL;
    RET_ERR(PsCreateThread(Process, NULL, NULL, Driver, PS_CREATE_THREAD_SUSPENDED, &Thread));
    assert(Thread != NULL);
    assert(Thread->InitialThread);
    PNTDLL_PROCESS_INIT_INFO InitInfo = (PVOID)Thread->IpcBufferServerAddr;

    /* Create the event loop notification in the driver's process-wide shared CNode and
     * derive the notification that the NT Executive signals when IO packets are available
     * for the driver to process. */
    RET_ERR(KeCreateNotificationEx(&Driver->EventLoopNotification, Process->SharedCNode));
    InitInfo->DriverInitInfo.EventLoopNotificationCap =
	Process->InitInfo.DriverInitInfo.EventLoopNotificationCap =
	Driver->EventLoopNotification.TreeNode.Cap;
    extern CNODE MiNtosCNode;
    RET_ERR(KeDeriveNotification(&Driver->IoPacketNotification, &MiNtosCNode,
				 &Driver->EventLoopNotification, 0));

    /* Derive the notification that the driver event loop thread signals so the NT
     * Executive will process the IO packets sent from the driver. */
    RET_ERR(KeEnableDriverServiceNotification(&Driver->ServiceNotification,
					      Thread->CSpace,
					      Driver->SignalGroupIndex));
    InitInfo->DriverInitInfo.ExecutiveNotificationCap =
	Process->InitInfo.DriverInitInfo.ExecutiveNotificationCap =
	PsThreadCNodeIndexToGuardedCap(Driver->ServiceNotification.TreeNode.Cap, 0, Thread);

    /* We place the IO_PACKET_BUFFER_POINTERS structure at the end of the TEB page
     * of the event loop thread. */
    Driver->IoPacketBufferPointers = (PVOID)(Thread->IpcBufferServerAddr + NT_TIB_OFFSET +
					     NT_TIB_COMMIT - sizeof(IO_PACKET_BUFFER_POINTERS));

    PsResumeThread(Thread);

    return STATUS_SUCCESS;
}

/*
 * Clean up the interrupt service and delete the INTERRUPT_SERVICE object.
 * This routine does not terminate the ISR thread.
 */
static inline VOID IopDeleteInterruptService(IN PINTERRUPT_SERVICE Svc)
{
    RemoveEntryList(&Svc->Link);
    if (Svc->IrqHandler.TreeNode.Cap != 0) {
	KeDestroyIrqHandler(&Svc->IrqHandler);
    }
    if (Svc->Notification.TreeNode.Cap != 0) {
	KeDestroyNotification(&Svc->Notification);
    }
    if (Svc->InterruptMutex.TreeNode.Cap != 0) {
	KeDestroyNotification(&Svc->InterruptMutex);
    }
    IopFreePool(Svc);
}

/* This is called by PsTerminateThread when the DPC or event loop thread of
 * a driver is being terminated, and by IoUnloadDriver when driver is being
 * unloaded. */
VOID IoUnlinkDriverFromServiceLoop(IN PIO_DRIVER_OBJECT DriverObject)
{
    DriverObject->DriverUnloading = TRUE;

    /* If the driver is in the pending driver list, remove it now. */
    if (DriverObject->PendingDriverLink.Blink) {
	assert(DriverObject->PendingDriverLink.Flink);
	RemoveEntryList(&DriverObject->PendingDriverLink);
    }

    /* If the driver has been assigned a signal group, remove it now. */
    if (DriverObject->SignalGroupLink.Blink) {
	assert(DriverObject->SignalGroupLink.Flink);
	RemoveEntryList(&DriverObject->SignalGroupLink);
    }
}

VOID IopDriverObjectDeleteProc(IN POBJECT Self)
{
    PIO_DRIVER_OBJECT Driver = Self;
    DbgTrace("Deleting driver object %p (%s)\n", Driver, Driver->DriverImagePath);

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

    /* If the driver has enabled the singleton IO timer object, delete it. */
    if (Driver->IoTimer.Notification.TreeNode.Cap) {
	KeRemoveIoTimer(&Driver->IoTimer);
	KeDestroyNotification(&Driver->IoTimer.Notification);
    }

    /* Unregister the PnP notifications if driver has registered them. */
    LoopOverList(Entry, &Driver->PlugPlayNotificationList,
		 PLUG_PLAY_NOTIFICATION, DriverLink) {
	IopUnregisterPlugPlayNotification(Entry);
    }
    assert(IsListEmpty(&Driver->PlugPlayNotificationList));

    /* Remove us from the bugcheck notification list, if registered. */
    if (ListHasEntry(&IoBugcheckNotificationList,
		     &Driver->BugcheckNotificationLink)) {
	RemoveEntryList(&Driver->BugcheckNotificationLink);
    }

    /* Note this may have already been done by IoUnloadDriver or NtTerminateProcess,
     * in which case this is a no-op. */
    IoUnlinkDriverFromServiceLoop(Driver);

    if (Driver->Node.Key) {
	PPROCESS DriverProcess = (PVOID)(ULONG_PTR)Driver->Node.Key;
	ObDereferenceObject(DriverProcess);
	AvlTreeRemoveNode(&IopDriverObjectTree, &Driver->Node);
    }
    if (Driver->DriverImagePath) {
	IopFreePool(Driver->DriverImagePath);
    }
    if (Driver->DriverRegistryPath) {
	IopFreePool(Driver->DriverRegistryPath);
    }
    KeUninitializeEvent(&Driver->InitializationDoneEvent);

    if (Driver->DpcMutex.TreeNode.Cap) {
	KeDestroyNotification(&Driver->DpcMutex);
    }
    if (Driver->WorkItemMutex.TreeNode.Cap) {
	KeDestroyNotification(&Driver->WorkItemMutex);
    }
#if defined(_M_IX86) || defined(_M_AMD64)
    if (Driver->X86PortMutex.TreeNode.Cap) {
	KeDestroyNotification(&Driver->X86PortMutex);
    }
#endif

    if (Driver->DpcNotification.TreeNode.Cap) {
	KeDestroyNotification(&Driver->DpcNotification);
    }
    if (Driver->BugcheckNotification.TreeNode.Cap) {
	KeDestroyNotification(&Driver->BugcheckNotification);
    }
    if (Driver->ServiceNotification.TreeNode.Cap) {
	KeDestroyNotification(&Driver->ServiceNotification);
    }
    if (Driver->IoPacketNotification.TreeNode.Cap) {
	KeDestroyNotification(&Driver->IoPacketNotification);
    }
    if (Driver->EventLoopNotification.TreeNode.Cap) {
	KeDestroyNotification(&Driver->EventLoopNotification);
    }
    if (Driver->TimerServiceEndpoint.TreeNode.Cap) {
	KeDestroyEndpoint(&Driver->TimerServiceEndpoint);
    }

    /* Clean up all interrupt services. Note that we do not need to terminate the ISR
     * threads here as that is done when the driver process terminates. */
    LoopOverList(Svc, &Driver->InterruptServiceList, INTERRUPT_SERVICE, Link) {
	IopDeleteInterruptService(Svc);
    }

    /* Purge the cache space and flush the dirty data into the shared cache maps. */
    if (Driver->CacheSpace) {
	CcUninitializeCacheSpace(Driver->CacheSpace);
    }

#if defined(_M_IX86) || defined(_M_AMD64)
    /* Close all x86 IO ports */
    LoopOverList(IoPort, &Driver->IoPortList, X86_IOPORT, Link) {
	KeDisableIoPort(IoPort);
	RemoveEntryList(&IoPort->Link);
	IopFreePool(IoPort);
    }
#endif
}

/*
 * Create the driver object specified by the driver service path. If the driver
 * object already exists, this routine does nothing.
 */
NTSTATUS IopLoadDriver(IN ASYNC_STATE State,
		       IN PTHREAD Thread,
		       IN PCSTR DriverServicePath)
{
    NTSTATUS Status;
    ULONG RegValueType = 0;
    PCSTR DriverImagePath = NULL;
    POBJECT KeyObject = NULL;
    PVOID DriverImageHandle = NULL;
    PSECTION DriverImageSection = NULL;

    ASYNC_BEGIN(State, Locals, {
	    POBJECT DriverObjectDirectory;
	    PCSTR DriverName;
	    PCSTR DriverImagePath;
	    POBJECT KeyObject;
	    OB_OBJECT_ATTRIBUTES ObjectAttributes;
	    IO_OPEN_CONTEXT OpenContext;
	    PVOID DriverImageHandle;
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
     * "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\null" */
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

    AWAIT_EX(Status, ObOpenObjectByName, State, Locals,
	     Thread, Locals.ObjectAttributes, OBJECT_TYPE_FILE, FILE_EXECUTE,
	     (POB_OPEN_CONTEXT)&Locals.OpenContext, &DriverImageHandle);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }
    Status = ObReferenceObjectByHandle(Thread, DriverImageHandle, OBJECT_TYPE_FILE,
				       (PVOID *)&Locals.DriverImageFile);
    /* Since there is no async routine invocation between ObOpenObjectByName and
     * ObReferenceObjectByHandle, this handle cannot be closed by another thread.
     * Therefore ObReferenceObjectByHandle should always succeed. If it did not,
     * the NT executive must be in a badly inconsistent state, so we have no choice
     * but to bugcheck. */
    if (!NT_SUCCESS(Status)) {
	KeBugCheckMsg("IopLoadDriver: ObReferenceObjectByHandle should always succeed.");
    }
    Locals.DriverImageHandle = DriverImageHandle;
    AWAIT(NtClose, State, Locals, Thread, Locals.DriverImageHandle);
    Locals.DriverImageHandle = NULL;

    /* Create the driver image section */
    AWAIT_EX(Status, MmCreateSectionEx, State, Locals, Thread,
	     Locals.DriverImageFile, 0, PAGE_EXECUTE, SEC_IMAGE, &DriverImageSection);
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
    PPROCESS DriverProcess = IoDriverObjectToProcess(Locals.DriverObject);
    PTHREAD MainEventLoopThread = DriverProcess ?
	PsGetProcessInitialThread(DriverProcess) : NULL;
    if (MainEventLoopThread) {
	Status = MainEventLoopThread->ExitStatus;
    } else {
	Status = STATUS_UNSUCCESSFUL;
    }
    if (!NT_SUCCESS(Status)) {
	ObDereferenceObject(Locals.DriverObject);
    } else {
	Locals.DriverObject->DriverLoaded = TRUE;
    }

out:
    assert(!Locals.DriverImageHandle);
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

PIO_DRIVER_OBJECT IopGetDriverObject(IN PCSTR DriverName)
{
    POBJECT DriverObjectDirectory;
    NTSTATUS Status = ObReferenceObjectByName(DRIVER_OBJECT_DIRECTORY,
					      OBJECT_TYPE_DIRECTORY,
					      FALSE, NULL,
					      &DriverObjectDirectory);
    if (!NT_SUCCESS(Status)) {
	assert(FALSE);
	return NULL;
    }
    assert(DriverObjectDirectory);
    PIO_DRIVER_OBJECT DriverObject = NULL;
    ObReferenceObjectByName(DriverName, OBJECT_TYPE_DRIVER,
			    DriverObjectDirectory, FALSE,
			    (POBJECT *)&DriverObject);
    ObDereferenceObject(DriverObjectDirectory);
    ObDereferenceObject(DriverObject);
    return DriverObject;
}

/*
 * This routine dereferences the driver object that IopLoadDriver has created.
 *
 * At this point this routine is only called when the driver process has crashed.
 */
NTSTATUS IoUnloadDriver(IN ASYNC_STATE State,
			IN PTHREAD Thread,
			IN PIO_DRIVER_OBJECT DriverObject,
			IN BOOLEAN NormalExit,
			IN NTSTATUS ExitStatus)
{
    NTSTATUS Status;
    ASYNC_BEGIN(State);

    DbgTrace("Unloading driver %p (%s)\n", DriverObject,
	     KEDBG_PROCESS_TO_FILENAME(IoDriverObjectToProcess(DriverObject)));

    IoUnlinkDriverFromServiceLoop(DriverObject);

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
	IopRemoveDevice(DevObj, TRUE);
    }

    /* Dereference so when all its device object have been deleted, the driver object
     * itself will be deleted. */
    ObDereferenceObject(DriverObject);

    Status = STATUS_SUCCESS;
    ASYNC_END(State, Status);
}

NTSTATUS NtLoadDriver(IN ASYNC_STATE State,
		      IN PTHREAD Thread,
		      IN PCSTR DriverServicePath)
{
    return IopLoadDriver(State, Thread, DriverServicePath);
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
    assert(Count == 1 || Count == 2 || Count == 4);
    PPROCESS Process = Thread->Process;
    assert(Process != NULL);
    PIO_DRIVER_OBJECT DriverObject = IoGetDriverObjectFromProcess(Process);
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

NTSTATUS WdmDisableX86Port(IN ASYNC_STATE AsyncState,
			   IN PTHREAD Thread,
			   IN USHORT PortNum,
			   IN USHORT Count,
			   IN MWORD Cap)
{
#if defined(_M_IX86) || defined(_M_AMD64)
    assert(Thread != NULL);
    assert(Cap);
    assert(Count == 1 || Count == 2 || Count == 4);
    PPROCESS Process = Thread->Process;
    assert(Process != NULL);
    PIO_DRIVER_OBJECT DriverObject = IoGetDriverObjectFromProcess(Process);
    assert(DriverObject != NULL);

    LoopOverList(IoPort, &DriverObject->IoPortList, X86_IOPORT, Link) {
	if (IoPort->PortNum == PortNum) {
	    assert(IoPort->Count == Count);
	    assert(IoPort->TreeNode.Cap == Cap);
	    KeDisableIoPort(IoPort);
	    RemoveEntryList(&IoPort->Link);
	    IopFreePool(IoPort);
	    return STATUS_SUCCESS;
	}
    }
    assert(FALSE);
    return STATUS_INVALID_PARAMETER;
#else
    return STATUS_NOT_SUPPORTED;
#endif
}

static NTSTATUS IopCreateInterruptServiceThread(IN PTHREAD DriverThread,
						IN PPNP_BUS_INFORMATION BusInfo,
						IN ULONG SlotNumber,
						IN PCM_PARTIAL_RESOURCE_DESCRIPTOR Raw,
						IN ULONG Vector,
						IN PIO_INTERRUPT_SERVICE_THREAD_ENTRY EntryPoint,
						IN PVOID ClientSideContext,
						OUT PINTERRUPT_SERVICE *pSvc,
						OUT PTHREAD *pIsrThread)
{
    PPROCESS DriverProcess = DriverThread->Process;
    assert(DriverProcess != NULL);
    PIO_DRIVER_OBJECT DriverObject = IoGetDriverObjectFromProcess(DriverProcess);
    assert(DriverObject != NULL);
    assert(IoDriverObjectToProcess(DriverObject) == DriverProcess);
    assert(pSvc != NULL);
    NTSTATUS Status = STATUS_NTOS_BUG;
    IopAllocatePool(Svc, INTERRUPT_SERVICE);

    CONTEXT Context;
    memset(&Context, 0, sizeof(CONTEXT));
    KeSetThreadContextFromEntryPoint(&Context, EntryPoint, ClientSideContext);

    /* Create the driver ISR thread and copy its thread cap into the CSpace of the
     * calling thread, which will usually be the driver's main event loop thread. */
    PTHREAD IsrThread = NULL;
    IF_ERR_GOTO(err, Status,
		PsCreateThread(DriverProcess, &Context, NULL, NULL,
			       PS_CREATE_ISR_THREAD | PS_CREATE_THREAD_SUSPENDED,
			       &IsrThread));
    assert(IsrThread != NULL);
    IF_ERR_GOTO(err, Status,
		PsSetThreadPriority(IsrThread, DEVICE_INTERRUPT_MIN_LEVEL + Vector));

    /* Create a notification for driver ISR thread to use as the interrupt notification */
    IF_ERR_GOTO(err, Status,
		KeCreateNotificationEx(&Svc->Notification,
				       IsrThread->CSpace));

    /* Also create the mutex object (which is simply a notification) for the
     * client side to synchronize data access between ISR and the rest of the driver. */
    IF_ERR_GOTO(err, Status,
		KeCreateNotificationEx(&Svc->InterruptMutex, DriverProcess->SharedCNode));

    /* Connect the given interrupt vector to the interrupt thread */
    Svc->IrqHandler.Config.Word = 0;
    Svc->IrqHandler.Vector = Vector;
    if (Raw->Flags & CM_RESOURCE_INTERRUPT_MESSAGE) {
	Svc->IrqHandler.Irq = 0;
	Svc->IrqHandler.Config.Msi = 1;
	Svc->IrqHandler.Message = Raw->MessageInterrupt.Raw.MessageData;
	if (BusInfo->LegacyBusType == PCIBus) {
	    PCI_SLOT_NUMBER Slot = { .AsULONG = SlotNumber };
	    Svc->IrqHandler.Config.Bus = BusInfo->BusNumber;
	    Svc->IrqHandler.Config.Device = Slot.Bits.DeviceNumber;
	    Svc->IrqHandler.Config.Function = Slot.Bits.FunctionNumber;
	}
    } else {
	Svc->IrqHandler.Irq = Raw->Interrupt.Vector;
	if (Raw->Flags & CM_RESOURCE_INTERRUPT_LATCHED) {
	    Svc->IrqHandler.Config.Level = 0;
	} else {
	    Svc->IrqHandler.Config.Level = 1;
	}
	if (Raw->Flags & CM_RESOURCE_INTERRUPT_ACTIVE_LOW) {
	    Svc->IrqHandler.Config.Polarity = 1;
	} else {
	    Svc->IrqHandler.Config.Polarity = 0;
	}
    }
    IF_ERR_GOTO(err, Status,
		KeCreateIrqHandlerCapEx(&Svc->IrqHandler,
					IsrThread->CSpace));

    /* Assign a handle for the ISR thread in the driver process */
    IF_ERR_GOTO(err, Status, ObCreateHandle(DriverProcess, IsrThread, FALSE,
					    &Svc->ThreadHandle, NULL));

    Svc->Vector = Vector;
    InsertTailList(&DriverObject->InterruptServiceList, &Svc->Link);
    *pSvc = Svc;
    *pIsrThread = IsrThread;
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
	IopFreePool(Svc);
    }
    if (IsrThread != NULL) {
	PsTerminateThread(IsrThread, STATUS_UNSUCCESSFUL);
    }
    return Status;
}

NTSTATUS WdmConnectInterrupt(IN ASYNC_STATE AsyncState,
			     IN PTHREAD Thread,
			     IN ULONG Vector,
			     IN PIO_INTERRUPT_SERVICE_THREAD_ENTRY EntryPoint,
			     IN PVOID ClientSideContext, /* Context as in EntryPoint(Context) */
			     OUT HANDLE *ThreadHandle,
			     OUT MWORD *IrqHandler,
			     OUT MWORD *InterruptNotification,
			     OUT MWORD *InterruptMutex)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    PIO_DRIVER_OBJECT DriverObject = IoGetDriverObjectFromProcess(Thread->Process);
    assert(DriverObject != NULL);
    assert(Thread->InitialThread);
    /* Check if the interrupt resource has been assigned by the PnP manager. */
    PNP_BUS_INFORMATION BusInfo = {};
    ULONG SlotNumber = 0;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR Raw = NULL;
    if (!IopIsInterruptVectorAssigned(DriverObject, Vector,
				      &BusInfo, &SlotNumber, &Raw)) {
	return STATUS_ACCESS_DENIED;
    }
    assert(Raw);

    /* Create the interrupt service thread, together with the interrupt notification
     * and interrupt mutex object */
    PINTERRUPT_SERVICE Svc = NULL;
    PTHREAD IsrThread = NULL;
    RET_ERR(IopCreateInterruptServiceThread(Thread, &BusInfo, SlotNumber, Raw, Vector,
					    EntryPoint, ClientSideContext,
					    &Svc, &IsrThread));
    assert(Svc != NULL);
    assert(IsrThread != NULL);
    assert(IsrThread->IsrThread);

    *ThreadHandle = Svc->ThreadHandle;
    *IrqHandler = PsThreadCNodeIndexToGuardedCap(Svc->IrqHandler.TreeNode.Cap,
						 0, IsrThread);
    *InterruptNotification = PsThreadCNodeIndexToGuardedCap(Svc->Notification.TreeNode.Cap,
							    0, IsrThread);
    *InterruptMutex = Svc->InterruptMutex.TreeNode.Cap;
    return STATUS_SUCCESS;
}

NTSTATUS WdmCreateDpcThread(IN ASYNC_STATE AsyncState,
			    IN PTHREAD Thread,
			    IN PVOID EntryPoint,
			    OUT HANDLE *ThreadHandle,
			    OUT MWORD *WdmServiceCap,
			    OUT MWORD *DpcNotificationCap,
			    OUT MWORD *TimerServiceCap)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    PIO_DRIVER_OBJECT DriverObject = IoGetDriverObjectFromProcess(Thread->Process);
    assert(DriverObject != NULL);
    assert(Thread->InitialThread);

    LoopOverList(Entry, &Thread->Process->ThreadList, THREAD, ThreadListEntry) {
	if (Entry->DpcThread) {
	    return STATUS_ALREADY_INITIALIZED;
	}
    }

    CONTEXT Context;
    memset(&Context, 0, sizeof(CONTEXT));
    KeSetThreadContextFromEntryPoint(&Context, EntryPoint, NULL);

    PTHREAD DpcThread = NULL;
    NTSTATUS Status = PsCreateThread(Thread->Process, &Context, NULL, NULL,
				     PS_CREATE_THREAD_SUSPENDED | PS_CREATE_DPC_THREAD,
				     &DpcThread);
    if (!NT_SUCCESS(Status)) {
	goto err;
    }
    assert(DpcThread != NULL);
    assert(DpcThread->DpcThread);
    IF_ERR_GOTO(err, Status,
		PsSetThreadPriority(DpcThread, DISPATCH_LEVEL));

    /* Create a notification for DPC thread to synchronize access with the main thread */
    IF_ERR_GOTO(err, Status,
		KeCreateNotificationEx(&DriverObject->DpcNotification,
				       Thread->Process->SharedCNode));
    assert(DriverObject->DpcNotification.TreeNode.Cap);

    /* Derive the notification cap in the server CSpace so we can signal for timer
     * expiration. The cap has a badge indicating its purpose. */
    extern CNODE MiNtosCNode;
    IF_ERR_GOTO(err, Status,
		KeDeriveNotification(&DriverObject->IoTimer.Notification,
				     &MiNtosCNode,
				     &DriverObject->DpcNotification,
				     TIMER_NOTIFICATION_BADGE));
    KeAddIoTimer(&DriverObject->IoTimer);

    /* Likewise, derive a bugcheck notification cap so server can signal drivers
     * when it has bugchecked. */
    IF_ERR_GOTO(err, Status,
		KeDeriveNotification(&DriverObject->BugcheckNotification,
				     &MiNtosCNode,
				     &DriverObject->DpcNotification,
				     BUGCHECK_NOTIFICATION_BADGE));

    /* Derive the timer service endpoint with the global handle of the
     * IO_DRIVER_OBJECT as the badge. This endpoint cap is in the process
     * shared CNode. */
    IF_ERR_GOTO(err, Status,
		KeEnableIoTimerService(&DriverObject->TimerServiceEndpoint,
				       Thread->Process->SharedCNode,
				       OBJECT_TO_GLOBAL_HANDLE(DriverObject)));

    /* Assign a handle for the DPC thread in the driver process */
    IF_ERR_GOTO(err, Status, ObCreateHandle(Thread->Process, DpcThread,
					    FALSE, ThreadHandle, NULL));
    *WdmServiceCap =
	PsThreadCNodeIndexToGuardedCap(DpcThread->WdmServiceEndpoint->TreeNode.Cap,
				       0, DpcThread);
    *DpcNotificationCap = DriverObject->DpcNotification.TreeNode.Cap;
    *TimerServiceCap = DriverObject->TimerServiceEndpoint.TreeNode.Cap;
    return STATUS_SUCCESS;

err:
    if (DpcThread) {
	PsTerminateThread(DpcThread, STATUS_UNSUCCESSFUL);
    }
    if (DriverObject->IoTimer.Notification.TreeNode.Cap) {
	KeDestroyNotification(&DriverObject->IoTimer.Notification);
	KeRemoveIoTimer(&DriverObject->IoTimer);
    }
    if (DriverObject->BugcheckNotification.TreeNode.Cap) {
	KeDestroyNotification(&DriverObject->BugcheckNotification);
    }
    if (DriverObject->DpcNotification.TreeNode.Cap) {
	KeDestroyNotification(&DriverObject->DpcNotification);
    }
    if (DriverObject->TimerServiceEndpoint.TreeNode.Cap) {
	KeDestroyEndpoint(&DriverObject->TimerServiceEndpoint);
    }
    return Status;
}

NTSTATUS WdmRegisterBugcheckNotification(IN ASYNC_STATE State,
					 IN PTHREAD Thread)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    PIO_DRIVER_OBJECT DriverObject = IoGetDriverObjectFromProcess(Thread->Process);
    assert(DriverObject);
    if (!ListHasEntry(&IoBugcheckNotificationList,
		      &DriverObject->BugcheckNotificationLink)) {
	InsertTailList(&IoBugcheckNotificationList,
		       &DriverObject->BugcheckNotificationLink);
	return STATUS_SUCCESS;
    }
    return STATUS_ALREADY_REGISTERED;
}

NTSTATUS WdmUnregisterBugcheckNotification(IN ASYNC_STATE State,
					   IN PTHREAD Thread)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    PIO_DRIVER_OBJECT DriverObject = IoGetDriverObjectFromProcess(Thread->Process);
    assert(DriverObject);
    if (ListHasEntry(&IoBugcheckNotificationList,
		      &DriverObject->BugcheckNotificationLink)) {
	RemoveEntryList(&DriverObject->BugcheckNotificationLink);
	return STATUS_SUCCESS;
    }
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS WdmCreateCoroutineStack(IN ASYNC_STATE State,
				 IN PTHREAD Thread,
				 OUT PVOID *pStackTop)
{
    assert(Thread->Process != NULL);
    assert(IoGetDriverObjectFromProcess(Thread->Process) != NULL);
    assert(Thread->InitialThread);
    return PsMapDriverCoroutineStack(Thread->Process, (MWORD *)pStackTop);
}
