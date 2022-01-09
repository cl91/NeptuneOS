#include "iop.h"

NTSTATUS IopDriverObjectCreateProc(IN POBJECT Object,
				   IN PVOID CreaCtx)
{
    PIO_DRIVER_OBJECT Driver = (PIO_DRIVER_OBJECT) Object;
    PDRIVER_OBJ_CREATE_CONTEXT Ctx = (PDRIVER_OBJ_CREATE_CONTEXT)CreaCtx;
    PCSTR DriverToLoad = Ctx->DriverPath;
    PCSTR DriverName = Ctx->DriverName;
    InitializeListHead(&Driver->DeviceList);
    InitializeListHead(&Driver->IoPortList);
    InitializeListHead(&Driver->IoPacketQueue);
    InitializeListHead(&Driver->PendingIoPacketList);
    KeInitializeEvent(&Driver->InitializationDoneEvent, NotificationEvent);
    KeInitializeEvent(&Driver->IoPacketQueuedEvent, SynchronizationEvent);

    PIO_FILE_OBJECT DriverFile = NULL;
    RET_ERR(ObReferenceObjectByName(DriverToLoad, OBJECT_TYPE_MASK_FILE,
				    NULL, (POBJECT *) &DriverFile));
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
    RET_ERR(PsCreateThread(Process, &Thread));
    assert(Thread != NULL);
    Driver->MainEventLoopThread = Thread;

    /* Insert the driver object to the \Driver object directory. */
    RET_ERR(ObInsertObjectByName(DRIVER_OBJECT_DIRECTORY, Driver, DriverName));

    return STATUS_SUCCESS;
}

NTSTATUS IoLoadDriver(IN PCSTR DriverToLoad,
		      OUT OPTIONAL PIO_DRIVER_OBJECT *pDriverObject)
{
    /* Find the driver basename, ie. "null.sys" in "\\BootModules\\null.sys" */
    SIZE_T PathLen = strlen(DriverToLoad);
    /* Start from the last non-nul byte, look for the path separator '\\' */
    SIZE_T SepIndex = 0;
    for (SIZE_T i = PathLen-1; i > 0; i--) {
	if (DriverToLoad[i] == OBJ_NAME_PATH_SEPARATOR) {
	    SepIndex = i;
	    break;
	}
    }
    PCSTR DriverName = &DriverToLoad[SepIndex+1];
    /* DriverName must not be null */
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
    DbgTrace("Object file %s driver name %s driver object %s\n", DriverToLoad, DriverName, DriverObjectPath);
    PIO_DRIVER_OBJECT DriverObject = NULL;
    if (NT_SUCCESS(ObReferenceObjectByName(DriverObjectPath, OBJECT_TYPE_MASK_DRIVER,
					   NULL, (POBJECT *)&DriverObject))) {
	/* Driver is already loaded. */
	/* TODO: Check if it's the same driver. For now we return SUCCESS */
	return STATUS_NTOS_DRIVER_ALREADY_LOADED;
    }

    /* Allocate the DriverObject */
    DRIVER_OBJ_CREATE_CONTEXT CreaCtx = {
	.DriverPath = DriverToLoad,
	.DriverName = DriverName
    };
    RET_ERR(ObCreateObject(OBJECT_TYPE_DRIVER, (POBJECT *) &DriverObject, &CreaCtx));
    assert(DriverObject != NULL);

    if (pDriverObject) {
	*pDriverObject = DriverObject;
    }
    return STATUS_SUCCESS;
}

NTSTATUS NtLoadDriver(IN ASYNC_STATE State,
		      IN PTHREAD Thread,
		      IN PCSTR DriverServiceName)
{
    PIO_DRIVER_OBJECT DriverObject = Thread->NtLoadDriverSavedState.DriverObject;

    ASYNC_BEGIN(State);

    NTSTATUS Status = IoLoadDriver(DriverServiceName, &DriverObject);
    if (Status == STATUS_NTOS_DRIVER_ALREADY_LOADED) {
	return STATUS_SUCCESS;
    }
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    assert(DriverObject != NULL);
    Thread->NtLoadDriverSavedState.DriverObject = DriverObject;

    AWAIT(KeWaitForSingleObject, State, Thread,
	  &DriverObject->InitializationDoneEvent.Header, FALSE);

    /* If the driver initialization failed, inform the caller of the error status */
    if (DriverObject->MainEventLoopThread == NULL) {
	return STATUS_UNSUCCESSFUL;
    }
    if (!NT_SUCCESS(DriverObject->MainEventLoopThread->ExitStatus)) {
	return DriverObject->MainEventLoopThread->ExitStatus;
    }
    /* This is strictly speaking unnecessary but it's safer to clear the saved state */
    Thread->NtLoadDriverSavedState.DriverObject = NULL;

    ASYNC_END(STATUS_SUCCESS);
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

NTSTATUS IopCreateWorkerThread(IN ASYNC_STATE AsyncState,
                               IN PTHREAD Thread,
                               IN PIO_WORKER_THREAD_ENTRY WorkerThreadEntry,
                               OUT HANDLE *WorkerThreadHandle,
                               OUT MWORD *WorkerThreadNotification)
{
    UNIMPLEMENTED;
}

NTSTATUS IopCreateInterruptServiceThread(IN ASYNC_STATE AsyncState,
                                         IN PTHREAD Thread,
                                         IN PIO_INTERRUPT_SERVICE_THREAD_ENTRY ThreadEntry,
                                         OUT HANDLE *ThreadHandle,
                                         OUT MWORD *ThreadNotification,
                                         OUT MWORD *InterruptMutex)
{
    UNIMPLEMENTED;
}
