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
	ExFreePool(DriverObjectPath);
	if (pDriverObject) {
	    *pDriverObject = DriverObject;
	}
	return STATUS_SUCCESS;
    }
    ExFreePool(DriverObjectPath);

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
	       ExFreePool(IoPort));
    InsertTailList(&DriverObject->IoPortList, &IoPort->Link);
    *Cap = IoPort->TreeNode.Cap;
    return STATUS_SUCCESS;
}

NTSTATUS IopCreateInterruptServiceThread(IN ASYNC_STATE AsyncState,
                                         IN PTHREAD Thread,
                                         IN PIO_INTERRUPT_SERVICE_THREAD_ENTRY EntryPoint,
                                         OUT HANDLE *ThreadHandle,
                                         OUT MWORD *ThreadNotification,
                                         OUT MWORD *InterruptMutex)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    assert(Thread->Process->DriverObject != NULL);
    assert(ThreadHandle != NULL);
    assert(ThreadNotification != NULL);
    assert(InterruptMutex != NULL);
    IopAllocatePool(IsrThread, INTERRUPT_SERVICE_THREAD);
    RET_ERR_EX(KeCreateNotification(&IsrThread->Notification),
	       ExFreePool(IsrThread));
    RET_ERR_EX(MmCapTreeDeriveBadgedNode(&IsrThread->ClientNotification.TreeNode,
					 &IsrThread->Notification.TreeNode,
					 seL4_AllRights, 0),
	       {
		   KeDestroyNotification(&IsrThread->Notification);
		   ExFreePool(IsrThread);
	       });
    CONTEXT Context;
    memset(&Context, 0, sizeof(CONTEXT));
    KeSetThreadContextFromEntryPoint(&Context, EntryPoint,
				     (PVOID)IsrThread->ClientNotification.TreeNode.Cap);
    RET_ERR_EX(KeCreateNotificationEx(&IsrThread->InterruptMutex,
				      Thread->Process->CSpace),
	       {
		   KeDestroyNotification(&IsrThread->Notification);
		   ExFreePool(IsrThread);
	       });
    RET_ERR_EX(PsCreateThread(Thread->Process, &Context, NULL,
			      FALSE, &IsrThread->Thread),
	       {
		   KeDestroyNotification(&IsrThread->Notification);
		   KeDestroyNotification(&IsrThread->InterruptMutex);
		   ExFreePool(IsrThread);
	       });
    assert(IsrThread->Thread != NULL);
    RET_ERR_EX(ObCreateHandle(Thread->Process,
			      IsrThread->Thread, ThreadHandle),
	       {
		   ObDereferenceObject(IsrThread->Thread);
		   KeDestroyNotification(&IsrThread->Notification);
		   KeDestroyNotification(&IsrThread->InterruptMutex);
		   ExFreePool(IsrThread);
	       });
    *ThreadNotification = IsrThread->ClientNotification.TreeNode.Cap;
    *InterruptMutex = IsrThread->InterruptMutex.TreeNode.Cap;
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
