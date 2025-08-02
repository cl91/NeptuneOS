/*++

Copyright (C) Microsoft Corporation, 1991 - 1999

Module Name:

    clntirp.c

Abstract:

    Client IRP queuing routines for CLASSPNP

Environment:

    kernel mode only

Notes:


Revision History:

--*/

#include "classp.h"
#include "debug.h"

static VOID ClasspServiceIdleRequest(PFUNCTIONAL_DEVICE_EXTENSION FdoExtension,
				     BOOLEAN PostToTimer);

/*++

EnqueueDeferredClientIrp

Routine Description:

    Insert the deferred irp into the list.

    Note: we currently do not support Cancel for storage irps.

Arguments:

    Fdo - Pointer to the device object
    Irp     - Pointer to the I/O request packet

Return Value:

    None

--*/
VOID EnqueueDeferredClientIrp(PDEVICE_OBJECT Fdo, PIRP Irp)
{
    PFUNCTIONAL_DEVICE_EXTENSION fdoExtension = Fdo->DeviceExtension;
    PCLASS_PRIVATE_FDO_DATA fdoData = fdoExtension->PrivateFdoData;
    InsertTailList(&fdoData->DeferredClientIrpList, &Irp->Tail.ListEntry);
}

/*++

DequeueDeferredClientIrp

Routine Description:

    Remove the deferred irp from the list.

Arguments:

    Fdo - Pointer to the device object

Return Value:

    Pointer to removed IRP

--*/
PIRP DequeueDeferredClientIrp(PDEVICE_OBJECT Fdo)
{
    PFUNCTIONAL_DEVICE_EXTENSION fdoExtension = Fdo->DeviceExtension;
    PCLASS_PRIVATE_FDO_DATA fdoData = fdoExtension->PrivateFdoData;
    PIRP irp;

    //
    // The DeferredClientIrpList is almost always empty.
    // We don't want to grab the spinlock every time we check it (which is on
    // every xfer completion) so check once first before we grab the spinlock.
    //
    if (IsListEmpty(&fdoData->DeferredClientIrpList)) {
	irp = NULL;
    } else {
	PLIST_ENTRY listEntry;
	if (IsListEmpty(&fdoData->DeferredClientIrpList)) {
	    listEntry = NULL;
	} else {
	    listEntry = RemoveHeadList(&fdoData->DeferredClientIrpList);
	}

	if (listEntry == NULL) {
	    irp = NULL;
	} else {
	    irp = CONTAINING_RECORD(listEntry, IRP, Tail.ListEntry);
	    NT_ASSERT(irp->Type == IO_TYPE_IRP);

	    InitializeListHead(&irp->Tail.ListEntry);
	}
    }

    return irp;
}

/*++

ClasspInitializeIdleTimer

Routine Description:

    Initialize the idle timer for the given device.

Arguments:

    FdoExtension    - Pointer to the device extension

Return Value:

    None

--*/
NTSTATUS ClasspInitializeIdleTimer(IN PDEVICE_OBJECT Fdo,
				   IN PFUNCTIONAL_DEVICE_EXTENSION FdoExtension)
{
    PCLASS_PRIVATE_FDO_DATA fdoData = FdoExtension->PrivateFdoData;
    ULONG idleInterval = CLASS_IDLE_INTERVAL;
    ULONG idlePrioritySupported = TRUE;
    ULONG activeIdleIoMax = 1;

    ClassGetDeviceParameter(FdoExtension, CLASSP_REG_SUBKEY_NAME,
			    CLASSP_REG_IDLE_PRIORITY_SUPPORTED, &idlePrioritySupported);

    if (idlePrioritySupported == FALSE) {
	//
	// User has set the registry to disable idle priority for this disk.
	// No need to initialize any further.
	// Always ensure that none of the other fields used for idle priority
	// io are ever used without checking if it is supported.
	//
	TracePrint((TRACE_LEVEL_INFORMATION, TRACE_FLAG_TIMER,
		    "ClasspInitializeIdleTimer: Idle priority not supported for disk "
		    "%p\n",
		    FdoExtension));
	fdoData->IdlePrioritySupported = FALSE;
	fdoData->IdleIoCount = 0;
	fdoData->ActiveIoCount = 0;
	return STATUS_SUCCESS;
    }

    ClassGetDeviceParameter(FdoExtension, CLASSP_REG_SUBKEY_NAME,
			    CLASSP_REG_IDLE_INTERVAL_NAME, &idleInterval);

    if ((idleInterval < CLASS_IDLE_INTERVAL_MIN) || (idleInterval > USHORT_MAX)) {
	//
	// If the interval is too low or too high, reset it to the default value.
	//
	idleInterval = CLASS_IDLE_INTERVAL;
    }

    fdoData->IdlePrioritySupported = TRUE;
    KeInitializeTimer(&fdoData->IdleTimer);
    fdoData->IdleWorkItem = IoAllocateWorkItem(Fdo);
    if (!fdoData->IdleWorkItem) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    InitializeListHead(&fdoData->IdleIrpList);
    fdoData->IdleTimerStarted = FALSE;
    fdoData->StarvationDuration = CLASS_STARVATION_INTERVAL;
    fdoData->IdleInterval = (USHORT)(idleInterval);
    fdoData->IdleIoCount = 0;
    fdoData->ActiveIoCount = 0;
    fdoData->ActiveIdleIoCount = 0;

    ClassGetDeviceParameter(FdoExtension, CLASSP_REG_SUBKEY_NAME,
			    CLASSP_REG_IDLE_ACTIVE_MAX, &activeIdleIoMax);

    activeIdleIoMax = max(activeIdleIoMax, 1);
    activeIdleIoMax = min(activeIdleIoMax, USHORT_MAX);

    fdoData->IdleActiveIoMax = (USHORT)activeIdleIoMax;

    return STATUS_SUCCESS;
}

/*++

ClasspGetIdleTime

Routine Description:

    This routine returns how long it has been since the last non-idle request
    completed by checking the actual time.

Arguments:

    FdoData - Pointer to the private fdo data

Return Value:

    The idle interval in ms.

--*/
static ULONGLONG ClasspGetIdleTime(IN PCLASS_PRIVATE_FDO_DATA FdoData,
				   IN LARGE_INTEGER CurrentTime)
{
    ULONGLONG idleTime;
    NTSTATUS status;

    //
    // Get the time difference between current time and last I/O
    // complete time.
    //

    status = RtlULongLongSub((ULONGLONG)CurrentTime.QuadPart,
			     (ULONGLONG)FdoData->LastNonIdleIoTime.QuadPart, &idleTime);

    if (NT_SUCCESS(status)) {
	//
	// Convert the time to milliseconds.
	//
	idleTime = ClasspTimeDiffToMs(idleTime);
    } else {
	//
	// Failed to get time difference, assume enough time passed.
	//
	idleTime = FdoData->IdleInterval;
    }

    return idleTime;
}

/*++

ClasspIdleDurationSufficient

Routine Description:

    This routine computes whether enough idle duration has elapsed since the
    completion of the last non-idle request.

Arguments:

    FdoData - Pointer to the private fdo data

    CurrentTimeIn - If CurrentTimeIn is non-NULL
        - contents are set to NULL if the time is not updated.
        - time is updated otherwise

Return Value:

    TRUE if sufficient idle duration has elapsed to issue the next idle request.

--*/
static BOOLEAN ClasspIdleDurationSufficient(IN PCLASS_PRIVATE_FDO_DATA FdoData,
					    OUT LARGE_INTEGER **CurrentTimeIn)
{
    ULONGLONG idleInterval;
    LARGE_INTEGER CurrentTime;

    //
    // If there are any outstanding non-idle requests, then there has been no
    // idle time.
    //
    if (FdoData->ActiveIoCount > 0) {
	if (CurrentTimeIn != NULL) {
	    *CurrentTimeIn = NULL;
	}
	return FALSE;
    }

    //
    // Check whether an idle request should be issued now or on the next timer
    // expiration.
    //

    CurrentTime = ClasspGetCurrentTime();
    idleInterval = ClasspGetIdleTime(FdoData, CurrentTime);

    if (CurrentTimeIn != NULL) {
	**CurrentTimeIn = CurrentTime;
    }

    if (idleInterval >= FdoData->IdleInterval) {
	return TRUE;
    }

    return FALSE;
}

/*++

ClasspIdleTimerWorkerRoutine

Routine Description:

    Timer worker function. This function will be called once every
    IdleInterval. An idle request will be queued if sufficient idle time
    has elapsed since the last non-idle request.

Arguments:

    DeviceObject    - Pointer to device object
    Context         - Pointer to the private FDO data

Return Value:

    None

--*/
static NTAPI VOID ClasspIdleTimerWorkerRoutine(IN PDEVICE_OBJECT DevObj,
					       IN PVOID Context)
{
    PFUNCTIONAL_DEVICE_EXTENSION fdoExtension = DevObj->DeviceExtension;
    PCLASS_PRIVATE_FDO_DATA fdoData = Context;
    ULONGLONG idleTime;
    NTSTATUS status;
    LARGE_INTEGER currentTime;
    LARGE_INTEGER *pCurrentTime;

    if (fdoExtension == NULL) {
	NT_ASSERT(fdoExtension != NULL);
	return;
    }

    fdoData = fdoExtension->PrivateFdoData;

    if (fdoData->ActiveIoCount <= 0) {
	//
	// If there are max active idle requests, do not issue another one here.
	//
	if (fdoData->ActiveIdleIoCount >= fdoData->IdleActiveIoMax) {
	    return;
	}

	//
	// Check whether enough idle time has passed since the last non-idle
	// request has completed.
	//

	pCurrentTime = &currentTime;
	if (ClasspIdleDurationSufficient(fdoData, &pCurrentTime)) {
	    //
	    // We are going to issue an idle request so reset the anti-starvation
	    // timer counter.
	    // If we are here (Idle duration is sufficient), pCurrentTime is
	    // expected to be set.
	    //
	    NT_ASSERT(pCurrentTime != NULL);
	    fdoData->AntiStarvationStartTime = *pCurrentTime;
	    ClasspServiceIdleRequest(fdoExtension, FALSE);
	}
	return;
    }

    //
    // Get the time difference between current time and last I/O
    // complete time.
    //

    currentTime = ClasspGetCurrentTime();
    status = RtlULongLongSub((ULONGLONG)currentTime.QuadPart,
			     (ULONGLONG)fdoData->AntiStarvationStartTime.QuadPart,
			     &idleTime);

    if (NT_SUCCESS(status)) {
	//
	// Convert the time to milliseconds.
	//
	idleTime = ClasspTimeDiffToMs(idleTime);
    } else {
	//
	// Failed to get time difference, assume enough time passed.
	//
	idleTime = fdoData->StarvationDuration;
    }

    //
    // If the timer is running then there must be at least one idle priority I/O pending
    //
    if (idleTime >= fdoData->StarvationDuration) {
	fdoData->AntiStarvationStartTime = currentTime;
	TracePrint((TRACE_LEVEL_INFORMATION, TRACE_FLAG_TIMER,
		    "ClasspIdleTimerWorkerRoutine: Starvation timer. Send one idle request\n"));
	ClasspServiceIdleRequest(fdoExtension, FALSE);
    }
    return;
}

/*++

ClasspStartIdleTimer

Routine Description:

    Start the idle timer if not already running. Reset the
    timer counters before starting the timer. Use the IdleInterval
    in the private fdo data to setup the timer.

Arguments:

    FdoData - Pointer to the private fdo data

Return Value:

    None

--*/
static VOID ClasspStartIdleTimer(IN PCLASS_PRIVATE_FDO_DATA FdoData)
{
    LARGE_INTEGER dueTime;
    LONG mstotimer;
    LONG timerStarted;

    TracePrint((TRACE_LEVEL_INFORMATION, TRACE_FLAG_TIMER,
		"ClasspStartIdleTimer: Start idle timer\n"));

    timerStarted = InterlockedCompareExchange(&FdoData->IdleTimerStarted, 1, 0);

    if (!timerStarted) {
	//
	// Reset the anti-starvation start time.
	//
	FdoData->AntiStarvationStartTime = ClasspGetCurrentTime();

	//
	// convert milliseconds to a relative 100ns
	//
	mstotimer = (-10) * 1000;

	//
	// multiply the period
	//
	dueTime.QuadPart = Int32x32To64(FdoData->IdleInterval, mstotimer);

	KeSetLowPriorityTimer(&FdoData->IdleTimer, dueTime, FdoData->IdleInterval,
			      FdoData->IdleWorkItem, ClasspIdleTimerWorkerRoutine, FdoData);
    }
    return;
}

/*++

ClasspStopIdleTimer

Routine Description:

    Stop the idle timer if running. Also reset the timer counters.

Arguments:

    FdoData - Pointer to the private fdo data

Return Value:

    None

--*/
static VOID ClasspStopIdleTimer(PCLASS_PRIVATE_FDO_DATA FdoData)
{
    LONG timerStarted;

    TracePrint((TRACE_LEVEL_INFORMATION, TRACE_FLAG_TIMER,
		"ClasspStopIdleTimer: Stop idle timer\n"));

    timerStarted = InterlockedCompareExchange(&FdoData->IdleTimerStarted, 0, 1);

    if (timerStarted) {
	(VOID) KeCancelTimer(&FdoData->IdleTimer);
    }
    return;
}

/*++

ClasspEnqueueIdleRequest

Routine Description:

    This function will insert the idle request into the list.
    If the inserted reqeust is the first request then it will
    start the timer.

Arguments:

    DeviceObject    - Pointer to device object
    Irp             - Pointer to the idle I/O request packet

Return Value:

    NT status code.

--*/
NTSTATUS ClasspEnqueueIdleRequest(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PFUNCTIONAL_DEVICE_EXTENSION fdoExtension = DeviceObject->DeviceExtension;
    PCLASS_PRIVATE_FDO_DATA fdoData = fdoExtension->PrivateFdoData;
    BOOLEAN issueRequest = TRUE;
    LARGE_INTEGER currentTime;
    LARGE_INTEGER *pCurrentTime;

    TracePrint((TRACE_LEVEL_INFORMATION, TRACE_FLAG_TIMER,
		"ClasspEnqueueIdleRequest: Queue idle request %p\n", Irp));

    IoMarkIrpPending(Irp);

    //
    // Reset issueRequest if the idle duration is not sufficient.
    //
    pCurrentTime = &currentTime;
    if (ClasspIdleDurationSufficient(fdoData, &pCurrentTime) == FALSE) {
	issueRequest = FALSE;
    }

    //
    // If there are already max active idle requests in the port driver, then
    // queue this idle request.
    //
    if (fdoData->ActiveIdleIoCount >= fdoData->IdleActiveIoMax) {
	issueRequest = FALSE;
    }

    if (IsListEmpty(&fdoData->IdleIrpList)) {
	NT_ASSERT(fdoData->IdleIoCount == 0);
    }
    InsertTailList(&fdoData->IdleIrpList, &Irp->Tail.ListEntry);

    fdoData->IdleIoCount++;
    if (!fdoData->IdleTimerStarted) {
	ClasspStartIdleTimer(fdoData);
    }

    if (fdoData->IdleIoCount != 1) {
	issueRequest = FALSE;
    }

    if (issueRequest) {
	ClasspServiceIdleRequest(fdoExtension, FALSE);
    }

    return STATUS_PENDING;
}

/*++

ClasspDequeueIdleRequest

Routine Description:

    This function will remove the next idle request from the list.
    If there are no requests in the queue, then it will return NULL.

Arguments:

    FdoExtension         - Pointer to the functional device extension

Return Value:

    Pointer to removed IRP

--*/
static PIRP ClasspDequeueIdleRequest(PFUNCTIONAL_DEVICE_EXTENSION FdoExtension)
{
    PCLASS_PRIVATE_FDO_DATA fdoData = FdoExtension->PrivateFdoData;
    PLIST_ENTRY listEntry = NULL;
    PIRP irp = NULL;

    if (fdoData->IdleIoCount > 0) {
	listEntry = RemoveHeadList(&fdoData->IdleIrpList);
	//
	// Make sure we actaully removed a request from the list
	//
	NT_ASSERT(listEntry != &fdoData->IdleIrpList);
	//
	// Decrement the idle I/O count.
	//
	fdoData->IdleIoCount--;
	//
	// Stop the timer on last request
	//
	if (fdoData->IdleIoCount == 0) {
	    ClasspStopIdleTimer(fdoData);
	}
	irp = CONTAINING_RECORD(listEntry, IRP, Tail.ListEntry);
	NT_ASSERT(irp->Type == IO_TYPE_IRP);

	InitializeListHead(&irp->Tail.ListEntry);
    }

    return irp;
}

/*++

ClasspCompleteIdleRequest

Routine Description:

    This function will be called every time an idle request is completed.
    This will call ClasspServiceIdleRequest to process any other pending idle requests.

Arguments:

    FdoExtension    - Pointer to the device extension

Return Value:

    None

--*/
VOID ClasspCompleteIdleRequest(PFUNCTIONAL_DEVICE_EXTENSION FdoExtension)
{
    PCLASS_PRIVATE_FDO_DATA fdoData = FdoExtension->PrivateFdoData;

    //
    // Issue the next idle request if there are any left in the queue, there are
    // no non-idle requests outstanding, there are less than max idle requests
    // outstanding, and it has been long enough since the completion of the last
    // non-idle request.
    //
    if ((fdoData->IdleIoCount > 0) &&
	(fdoData->ActiveIdleIoCount < fdoData->IdleActiveIoMax) &&
	(fdoData->ActiveIoCount <= 0) && (ClasspIdleDurationSufficient(fdoData, NULL))) {
	TracePrint((TRACE_LEVEL_INFORMATION, TRACE_FLAG_TIMER,
		    "ClasspCompleteIdleRequest: Service next idle reqeusts\n"));
	ClasspServiceIdleRequest(FdoExtension, TRUE);
    }

    return;
}

/*++

ClasspServiceIdleRequest

Routine Description:

    Remove the next pending idle request from the queue and process it.
    If a request was removed then it will be processed otherwise it will
    just return.

Arguments:

    FdoExtension    - Pointer to the device extension
    PostToTimer  - Flag to pass to ServiceTransferRequest to indicate if request must be posted to a timer work item

Return Value:

    None

--*/
VOID ClasspServiceIdleRequest(PFUNCTIONAL_DEVICE_EXTENSION FdoExtension,
			      BOOLEAN PostToTimer)
{
    PIRP irp;

    irp = ClasspDequeueIdleRequest(FdoExtension);
    if (irp != NULL) {
	ServiceTransferRequest(FdoExtension->DeviceObject, irp, PostToTimer);
    }
    return;
}
