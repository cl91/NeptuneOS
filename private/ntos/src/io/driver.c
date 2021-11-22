#include "iop.h"

NTSTATUS IopDriverObjectInitProc(POBJECT Object)
{
    PIO_DRIVER_OBJECT Driver = (PIO_DRIVER_OBJECT) Object;
    InitializeListHead(&Driver->DeviceList);
    InitializeListHead(&Driver->IrpQueue);
    InitializeListHead(&Driver->PendingIrpList);
    KeInitializeEvent(&Driver->InitializationDoneEvent, NotificationEvent);
    KeInitializeEvent(&Driver->IrpQueuedEvent, SynchronizationEvent);
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
    if (NT_SUCCESS(ObReferenceObjectByName(DriverObjectPath, OBJECT_TYPE_DRIVER, (POBJECT *)&DriverObject))) {
	/* Driver is already loaded. */
	/* TODO: Check if it's the same driver. For now we return SUCCESS */
	return STATUS_NTOS_DRIVER_ALREADY_LOADED;
    }

    /* Allocate the DriverObject */
    RET_ERR(ObCreateObject(OBJECT_TYPE_DRIVER, (POBJECT *) &DriverObject));
    assert(DriverObject != NULL);

    PIO_FILE_OBJECT DriverFile = NULL;
    RET_ERR_EX(ObReferenceObjectByName(DriverToLoad, OBJECT_TYPE_FILE, (POBJECT *) &DriverFile),
	       ObDereferenceObject(DriverObject));
    assert(DriverFile != NULL);

    /* Start the driver process */
    PPROCESS Process = NULL;
    RET_ERR_EX(PsCreateProcess(DriverFile, DriverObject, &Process),
	       ObDereferenceObject(DriverObject));
    assert(Process != NULL);

    /* Make sure we have loaded hal.dll, even when the driver image does not
     * explicitly depend on it. */
    RET_ERR_EX(PsLoadDll(Process, HAL_DLL_NAME),
	       ObDereferenceObject(DriverObject));

    /* Get the init thread of driver process running */
    PTHREAD Thread = NULL;
    RET_ERR_EX(PsCreateThread(Process, &Thread),
	       ObDereferenceObject(DriverObject));
    assert(Thread != NULL);

    /* Insert the driver object to the \Driver object directory. */
    RET_ERR_EX(ObInsertObjectByName(DRIVER_OBJECT_DIRECTORY, DriverObject, DriverName),
	       ObDereferenceObject(DriverObject));
    DriverObject->DriverProcess = Process;

    if (pDriverObject) {
	*pDriverObject = DriverObject;
    }
    return STATUS_SUCCESS;
}

NTSTATUS NtLoadDriver(IN ASYNC_STATE State,
		      IN PTHREAD Thread,
		      IN PCSTR DriverServiceName)
{
    PIO_DRIVER_OBJECT DriverObject = NULL;

    ASYNC_BEGIN(State);

    NTSTATUS Status = IoLoadDriver(DriverServiceName, &DriverObject);
    if (Status == STATUS_NTOS_DRIVER_ALREADY_LOADED) {
	return STATUS_SUCCESS;
    }
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    assert(DriverObject != NULL);

    /* The second time that this function is called, DriverObject is actually NULL here,
     * but that's fine since the event has been recorded into the thread's root wait block. */
    AWAIT(KeWaitForSingleObject, State, Thread, &DriverObject->InitializationDoneEvent.Header);

    ASYNC_END(STATUS_SUCCESS);
}
