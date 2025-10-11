// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  ec.c - ACPI Embedded Controller Driver (v3)
 *
 *  Copyright (C) 2001-2015 Intel Corporation
 *    Author: 2014, 2015 Lv Zheng <lv.zheng@intel.com>
 *            2006, 2007 Alexey Starikovskiy <alexey.y.starikovskiy@intel.com>
 *            2006       Denis Sadykov <denis.m.sadykov@intel.com>
 *            2004       Luming Yu <luming.yu@intel.com>
 *            2001, 2002 Andy Grover <andrew.grover@intel.com>
 *            2001, 2002 Paul Diefenbaugh <paul.s.diefenbaugh@intel.com>
 *  Copyright (C) 2008      Alexey Starikovskiy <astarikovskiy@suse.de>
 */

#include <stdio.h>
#include <intrin.h>
#include "../precomp.h"
#include <poclass.h>
#include "acpi_bus.h"
#include "acpi_drivers.h"

#define _COMPONENT ACPI_EC_COMPONENT
ACPI_MODULE_NAME("acpi_ec")

#define EC_DEVICE_ID	"PNP0C09"
#define ACPI_ECDT_HID	"LNXEC"

/* EC status register */
#define ACPI_EC_FLAG_OBF	0x01	/* Output buffer full */
#define ACPI_EC_FLAG_IBF	0x02	/* Input buffer full */
#define ACPI_EC_FLAG_CMD	0x08	/* Input buffer contains a command */
#define ACPI_EC_FLAG_BURST	0x10	/* burst mode */
#define ACPI_EC_FLAG_SCI	0x20	/* EC-SCI occurred */

/*
 * The SCI_EVT clearing timing is not defined by the ACPI specification.
 * This leads to lots of practical timing issues for the host EC driver.
 * The following variations are defined (from the target EC firmware's
 * perspective):
 * STATUS: After indicating SCI_EVT edge triggered IRQ to the host, the
 *         target can clear SCI_EVT at any time so long as the host can see
 *         the indication by reading the status register (EC_SC). So the
 *         host should re-check SCI_EVT after the first time the SCI_EVT
 *         indication is seen, which is the same time the query request
 *         (CMD_QUERY) is written to the command register (EC_CMD). SCI_EVT
 *         set at any later time could indicate another event. Normally
 *         such kind of EC firmware has implemented an event queue and will
 *         return 0x00 to indicate "no outstanding event".
 * QUERY: After seeing the query request (CMD_QUERY) written to the command
 *        register (EC_CMD) by the host and having prepared the responding
 *        event value in the data register (EC_DATA), the target can safely
 *        clear SCI_EVT because the target can confirm that the current
 *        event is being handled by the host. The host then should check
 *        SCI_EVT right after reading the event response from the data
 *        register (EC_DATA).
 * EVENT: After seeing the event response read from the data register
 *        (EC_DATA) by the host, the target can clear SCI_EVT. As the
 *        target requires time to notice the change in the data register
 *        (EC_DATA), the host may be required to wait additional guarding
 *        time before checking the SCI_EVT again. Such guarding may not be
 *        necessary if the host is notified via another IRQ.
 */
#define ACPI_EC_EVT_TIMING_STATUS	0x00
#define ACPI_EC_EVT_TIMING_QUERY	0x01
#define ACPI_EC_EVT_TIMING_EVENT	0x02

/* EC commands */
typedef enum _EC_COMMAND {
    ACPI_EC_COMMAND_READ = 0x80,
    ACPI_EC_COMMAND_WRITE = 0x81,
    ACPI_EC_COMMAND_ENABLE_BURST = 0x82,
    ACPI_EC_COMMAND_DISABLE_BURST = 0x83,
    ACPI_EC_COMMAND_QUERY = 0x84,
} EC_COMMAND;

#define ACPI_EC_DELAY		500	/* Wait 500ms max. during EC ops */
#define ACPI_EC_UDELAY_GLK	1000	/* Wait 1ms max. to get global lock */
#define ACPI_EC_UDELAY_POLL	550	/* Wait 550us for EC transaction polling */
#define ACPI_EC_CLEAR_MAX	100	/* Maximum number of events to query
					 * when trying to clear the EC */

enum {
    EC_FLAGS_QUERY_ENABLED,		/* Query is enabled */
    EC_FLAGS_EVENT_HANDLER_INSTALLED,	/* Event handler installed */
    EC_FLAGS_EC_HANDLER_INSTALLED,	/* OpReg handler installed */
    EC_FLAGS_EC_REG_CALLED,		/* OpReg ACPI _REG method called */
    EC_FLAGS_QUERY_METHODS_INSTALLED,	/* _Qxx handlers installed */
    EC_FLAGS_STARTED,			/* Driver is started */
    EC_FLAGS_STOPPED,			/* Driver is stopped */
    EC_FLAGS_EVENTS_MASKED,		/* Events masked */
};

#define ACPI_EC_COMMAND_POLL		0x01 /* Available for command byte */
#define ACPI_EC_COMMAND_COMPLETE	0x02 /* Completed last byte */

static ULONG AcpiEcDelay = ACPI_EC_DELAY;
static ULONG AcpiEcEventClearing = ACPI_EC_EVT_TIMING_QUERY;

/*
 * If the number of false interrupts per one transaction exceeds
 * this threshold, will think there is a GPE storm happened and
 * will disable the GPE for normal transaction.
 */
static ULONG AcpiEcStormThreshold = 8;

static BOOLEAN AcpiEcFreezeEvents;

typedef enum _ACPI_EC_EVENT_STATE {
    EC_EVENT_READY = 0,     /* Event work can be submitted */
    EC_EVENT_IN_PROGRESS,   /* Event work is pending or being processed */
    EC_EVENT_COMPLETE,      /* Event work processing has completed */
} ACPI_EC_EVENT_STATE;

typedef struct _ACPI_EC {
    ACPI_HANDLE Handle;
    ACPI_HANDLE AddressSpaceHandlerHolder;
    INT Gpe;
    ULONG_PTR CommandAddress;
    ULONG_PTR DataAddress;
    ULONG_PTR Flags;
    ULONG_PTR ReferenceCount;
    KEVENT CompletionEvent;
    LIST_ENTRY HandlerList;
    struct _EC_TRANSACTION *CurrentTransaction;
    IO_WORKITEM WorkItem;
    ACPI_EC_EVENT_STATE EventState;
    ULONG EventsToProcess;
    ULONG EventsInProgress;
    ULONG QueriesInProgress;
    BOOLEAN GlobalLock;
} ACPI_EC, *PACPI_EC;

typedef INT (*ACPI_EC_QUERY_FUNC)(PVOID Data);

typedef struct _ACPI_EC_QUERY_HANDLER {
    LIST_ENTRY Node;
    ACPI_EC_QUERY_FUNC Func;
    ACPI_HANDLE Handle;
    PVOID Data;
    UCHAR QueryBit;
} ACPI_EC_QUERY_HANDLER, *PACPI_EC_QUERY_HANDLER;

typedef struct _EC_TRANSACTION {
    const UCHAR *InputBuffer;	/* Data written to the EC */
    PUCHAR OutputBuffer;	/* Data read from the EC */
    USHORT IrqCount;
    UCHAR Command;
    UCHAR InputIndex;
    UCHAR OutputIndex;
    UCHAR InputLength;
    UCHAR OutputLength;
    UCHAR Flags;
} EC_TRANSACTION, *PEC_TRANSACTION;

typedef struct _ACPI_EC_QUERY {
    EC_TRANSACTION Transaction;
    PACPI_EC_QUERY_HANDLER Handler;
    PACPI_EC Ec;
} ACPI_EC_QUERY, *PACPI_EC_QUERY;

static ACPI_STATUS AcpiEcSubmitQuery(IN PDEVICE_OBJECT BusFdo, IN PACPI_EC Ec);
static VOID AdvanceTransaction(PACPI_EC Ec, BOOLEAN Interrupt);
static NTAPI VOID AcpiEcEventHandler(IN PDEVICE_OBJECT BusFdo,
				     IN PVOID Context);

static PACPI_EC AcpiFirstEc;
static PACPI_EC AcpiBootEc;
static BOOLEAN AcpiBootEcIsEcdt;

static int EcFlagsCorrectEcdt; /* Needs ECDT port address correction */
static int EcFlagsTrustDsdtGpe; /* Needs DSDT GPE as correction setting */
static int EcFlagsClearOnResume; /* Needs AcpiEcClear() on boot/resume */

/* --------------------------------------------------------------------------
 *                           Logging/Debugging
 * -------------------------------------------------------------------------- */

/*
 * Splitters used by the developers to track the boundary of the EC
 * handling processes.
 */
#if DBG
#define EC_DBG_SEP	" "
#define EC_DBG_DRV	"+++++"
#define EC_DBG_STM	"====="
#define EC_DBG_REQ	"*****"
#define EC_DBG_EVT	"#####"
#define EC_DBG_GPE	"....."
#else
#define EC_DBG_SEP	""
#define EC_DBG_DRV
#define EC_DBG_STM
#define EC_DBG_REQ
#define EC_DBG_EVT
#define EC_DBG_GPE
#endif

#define ACPI_HANDLE_DEBUG(Handle, Fmt, ...)			\
    INFO_(ACPI, "Handle %p: " Fmt, Handle, ##__VA_ARGS__)

#define ACPI_HANDLE_INFO	ACPI_HANDLE_DEBUG

#define EcLogRaw(fmt, ...)					\
    ACPI_DEBUG_PRINT((ACPI_DB_INFO, fmt "\n", ##__VA_ARGS__))
#define EcDbgRaw(fmt, ...)					\
    ACPI_DEBUG_PRINT((ACPI_DB_INFO, fmt "\n", ##__VA_ARGS__))
#define EcLog(filter, fmt, ...)						\
    EcLogRaw(filter EC_DBG_SEP fmt EC_DBG_SEP filter, ##__VA_ARGS__)
#define EcDbg(filter, fmt, ...)						\
    EcDbgRaw(filter EC_DBG_SEP fmt EC_DBG_SEP filter, ##__VA_ARGS__)

#define EcLogDrv(fmt, ...)			\
    EcLog(EC_DBG_DRV, fmt, ##__VA_ARGS__)
#define EcDbgDrv(fmt, ...)			\
    EcDbg(EC_DBG_DRV, fmt, ##__VA_ARGS__)
#define EcDbgStm(fmt, ...)			\
    EcDbg(EC_DBG_STM, fmt, ##__VA_ARGS__)
#define EcDbgReq(fmt, ...)			\
    EcDbg(EC_DBG_REQ, fmt, ##__VA_ARGS__)
#define EcDbgEvt(fmt, ...)			\
    EcDbg(EC_DBG_EVT, fmt, ##__VA_ARGS__)
#define EcDbgGpe(fmt, ...)			\
    EcDbg(EC_DBG_GPE, fmt, ##__VA_ARGS__)
#define EcDbgRef(ec, fmt, ...)					\
    EcDbgRaw("(EC refcount %zu): " fmt, ec->ReferenceCount, ## __VA_ARGS__)

#define BUG_ON(Cond)	ASSERT(!(Cond))

FORCEINLINE VOID AcpiEcAcquireLock()
{
    AcpiOsAcquireLock(NULL);
}

FORCEINLINE VOID AcpiEcReleaseLock()
{
    AcpiOsReleaseLock(NULL, 0);
}

FORCEINLINE BOOLEAN RequestRegion(IN ULONG_PTR Port,
				  IN ULONG Bytes,
				  IN PCSTR Info)
{
    ASSERT(Bytes < 4);
    INFO_(ACPI, "Requesting IO port 0x%zx length %d for %s\n",
	  Port, Bytes, Info);
    return NT_SUCCESS(IoEnablePort(Port, Bytes * 8));
}

/* --------------------------------------------------------------------------
 *                           Device Flags
 * -------------------------------------------------------------------------- */

FORCEINLINE BOOLEAN IsBitSet(IN UCHAR Bit, IN PULONG_PTR Flags)
{
    return *Flags & (1ULL << Bit);
}

FORCEINLINE VOID SetBit(IN UCHAR Bit, IN PULONG_PTR Flags)
{
    *Flags |= (1ULL << Bit);
}

FORCEINLINE VOID ClearBit(IN UCHAR Bit, IN PULONG_PTR Flags)
{
    *Flags &= ~(1ULL << Bit);
}

#define TestAndSetBit(Bit, Ptr)	InterlockedBitTestAndSetPointer(Ptr, Bit)
#define TestAndClearBit(Bit, Ptr) InterlockedBitTestAndResetPointer(Ptr, Bit)

static BOOLEAN AcpiEcIsStarted(PACPI_EC Ec)
{
    return IsBitSet(EC_FLAGS_STARTED, &Ec->Flags) &&
	!IsBitSet(EC_FLAGS_STOPPED, &Ec->Flags);
}

static BOOLEAN AcpiEcIsEventEnabled(PACPI_EC Ec)
{
    /*
     * There is an OSPM early stage logic. During the early stages
     * (boot/resume), OSPMs shouldn't enable the event handling, only
     * the EC transactions are allowed to be performed.
     */
    if (!IsBitSet(EC_FLAGS_QUERY_ENABLED, &Ec->Flags))
	return FALSE;
    /*
     * However, disabling the event handling is experimental for late
     * stage (suspend), and is controlled by the boot parameter of
     * "AcpiEcFreezeEvents":
     * 1. TRUE:  The EC event handling is disabled before entering
     *           the noirq stage.
     * 2. FALSE: The EC event handling is automatically disabled as
     *           soon as the EC driver is stopped.
     */
    if (AcpiEcFreezeEvents)
	return AcpiEcIsStarted(Ec);
    else
	return IsBitSet(EC_FLAGS_STARTED, &Ec->Flags);
}

static BOOLEAN AcpiEcIsFlushed(PACPI_EC Ec)
{
    return Ec->ReferenceCount == 1;
}

/* --------------------------------------------------------------------------
 *                           EC Registers
 * -------------------------------------------------------------------------- */

FORCEINLINE UCHAR AcpiEcReadStatus(PACPI_EC Ec)
{
    UCHAR Status = READ_PORT_UCHAR(Ec->CommandAddress);

    EcDbgRaw("EC_SC(R) = 0x%2.2x "
	     "SCI_EVT=%d BURST=%d CMD=%d IBF=%d OBF=%d",
	     Status,
	     !!(Status & ACPI_EC_FLAG_SCI),
	     !!(Status & ACPI_EC_FLAG_BURST),
	     !!(Status & ACPI_EC_FLAG_CMD),
	     !!(Status & ACPI_EC_FLAG_IBF),
	     !!(Status & ACPI_EC_FLAG_OBF));
    return Status;
}

FORCEINLINE UCHAR AcpiEcReadData(PACPI_EC Ec)
{
    UCHAR Data = READ_PORT_UCHAR(Ec->DataAddress);

    EcDbgRaw("EC_DATA(R) = 0x%2.2x", Data);
    return Data;
}

FORCEINLINE VOID AcpiEcWriteCmd(PACPI_EC Ec, UCHAR Command)
{
    EcDbgRaw("EC_SC(W) = 0x%2.2x", Command);
    WRITE_PORT_UCHAR(Ec->CommandAddress, Command);
}

FORCEINLINE void AcpiEcWriteData(PACPI_EC Ec, UCHAR Data)
{
    EcDbgRaw("EC_DATA(W) = 0x%2.2x", Data);
    WRITE_PORT_UCHAR(Ec->DataAddress, Data);
}

static PCSTR AcpiEcCmdToString(EC_COMMAND Cmd)
{
    switch (Cmd) {
    case ACPI_EC_COMMAND_READ:
	return "EC_CMD_READ";
    case ACPI_EC_COMMAND_WRITE:
	return "EC_CMD_WRITE";
    case ACPI_EC_COMMAND_ENABLE_BURST:
	return "EC_CMD_ENABLE_BURST_MODE";
    case ACPI_EC_COMMAND_DISABLE_BURST:
	return "EC_CMD_DISABLE_BURST_MODE";
    case ACPI_EC_COMMAND_QUERY:
	return "EC_CMD_QUERY";
    }
    return "UNKNOWN";
}

/* --------------------------------------------------------------------------
 *                           GPE Registers
 * -------------------------------------------------------------------------- */

FORCEINLINE BOOLEAN AcpiEcIsGpeStatusSet(PACPI_EC Ec)
{
    ACPI_EVENT_STATUS GpeStatus = 0;

    AcpiGetGpeStatus(NULL, Ec->Gpe, &GpeStatus);
    return !!(GpeStatus & ACPI_EVENT_FLAG_STATUS_SET);
}

FORCEINLINE VOID AcpiEcEnableGpe(PACPI_EC Ec, BOOLEAN Open)
{
    if (Open)
	AcpiEnableGpe(NULL, Ec->Gpe);
    else {
	BUG_ON(Ec->ReferenceCount < 1);
	AcpiSetGpe(NULL, Ec->Gpe, ACPI_GPE_ENABLE);
    }
    if (AcpiEcIsGpeStatusSet(Ec)) {
	/*
	 * On some platforms, EN=1 writes cannot trigger GPE. So
	 * software need to manually trigger a pseudo GPE event on
	 * EN=1 writes.
	 */
	EcDbgRaw("Polling quirk");
	AdvanceTransaction(Ec, FALSE);
    }
}

FORCEINLINE VOID AcpiEcDisableGpe(PACPI_EC Ec, BOOLEAN Close)
{
    if (Close)
	AcpiDisableGpe(NULL, Ec->Gpe);
    else {
	BUG_ON(Ec->ReferenceCount < 1);
	AcpiSetGpe(NULL, Ec->Gpe, ACPI_GPE_DISABLE);
    }
}

/* --------------------------------------------------------------------------
 *                           Transaction Management
 * -------------------------------------------------------------------------- */

static VOID AcpiEcSubmitRequest(PACPI_EC Ec)
{
    Ec->ReferenceCount++;
    if (IsBitSet(EC_FLAGS_EVENT_HANDLER_INSTALLED, &Ec->Flags) &&
	Ec->Gpe >= 0 && Ec->ReferenceCount == 1)
	AcpiEcEnableGpe(Ec, TRUE);
}

static VOID AcpiEcCompleteRequest(PACPI_EC Ec)
{
    BOOLEAN Flushed = FALSE;

    Ec->ReferenceCount--;
    if (IsBitSet(EC_FLAGS_EVENT_HANDLER_INSTALLED, &Ec->Flags) &&
	Ec->Gpe >= 0 && Ec->ReferenceCount == 0)
	AcpiEcDisableGpe(Ec, TRUE);
    Flushed = AcpiEcIsFlushed(Ec);
    if (Flushed)
	KeSetEvent(&Ec->CompletionEvent);
}

static VOID AcpiEcMaskEvents(PACPI_EC Ec)
{
    if (!IsBitSet(EC_FLAGS_EVENTS_MASKED, &Ec->Flags)) {
	if (Ec->Gpe >= 0)
	    AcpiEcDisableGpe(Ec, FALSE);

	EcDbgDrv("Polling enabled");
	SetBit(EC_FLAGS_EVENTS_MASKED, &Ec->Flags);
    }
}

static VOID AcpiEcUnmaskEvents(PACPI_EC Ec)
{
    if (IsBitSet(EC_FLAGS_EVENTS_MASKED, &Ec->Flags)) {
	ClearBit(EC_FLAGS_EVENTS_MASKED, &Ec->Flags);
	if (Ec->Gpe >= 0)
	    AcpiEcEnableGpe(Ec, FALSE);

	EcDbgDrv("Polling disabled");
    }
}

/*
 * AcpiEcSubmitFlushableRequest() - Increase the reference count unless
 *                                  the flush operation is not in
 *                                  progress
 * @ec: the EC device
 *
 * This function must be used before taking a new action that should hold
 * the reference count.  If this function returns FALSE, then the action
 * must be discarded or it will prevent the flush operation from being
 * completed.
 */
static BOOLEAN AcpiEcSubmitFlushableRequest(PACPI_EC Ec)
{
    if (!AcpiEcIsStarted(Ec))
	return FALSE;
    AcpiEcSubmitRequest(Ec);
    return TRUE;
}

static VOID AcpiEcSubmitEvent(PACPI_EC Ec)
{
    /*
     * It is safe to mask the events here, because AcpiEcCloseEvent()
     * will run at least once after this.
     */
    AcpiEcMaskEvents(Ec);
    if (!AcpiEcIsEventEnabled(Ec))
	return;

    if (Ec->EventState != EC_EVENT_READY)
	return;

    EcDbgEvt("Command(%s) submitted/blocked",
	     AcpiEcCmdToString(ACPI_EC_COMMAND_QUERY));

    Ec->EventState = EC_EVENT_IN_PROGRESS;
    /*
     * If EventsToProcess is greater than 0 at this point, the while ()
     * loop in AcpiEcEventHandler() is still running and incrementing
     * EventsToProcess will cause it to invoke AcpiEcSubmitQuery() once
     * more, so it is not necessary to queue up the event work to start
     * the same loop again.
     */
    if (Ec->EventsToProcess++ > 0)
	return;

    Ec->EventsInProgress++;
    if (NtCurrentTeb()->Wdm.IsIsrThread) {
	IoQueueWorkItem(&Ec->WorkItem, AcpiEcEventHandler, DelayedWorkQueue, Ec);
    } else {
	AcpiEcEventHandler(Ec->WorkItem.DeviceObject, Ec);
    }
}

static VOID AcpiEcCompleteEvent(PACPI_EC Ec)
{
    if (Ec->EventState == EC_EVENT_IN_PROGRESS)
	Ec->EventState = EC_EVENT_COMPLETE;
}

static VOID AcpiEcCloseEvent(PACPI_EC Ec)
{
    if (Ec->EventState != EC_EVENT_READY)
	EcDbgEvt("Command(%s) unblocked",
		 AcpiEcCmdToString(ACPI_EC_COMMAND_QUERY));

    Ec->EventState = EC_EVENT_READY;
    AcpiEcUnmaskEvents(Ec);
}

/*
 * Process _Q events that might have accumulated in the EC.
 */
static VOID AcpiEcClear(IN PDEVICE_OBJECT BusFdo,
			IN PACPI_EC Ec)
{
    int i;
    for (i = 0; i < ACPI_EC_CLEAR_MAX; i++) {
	if (!ACPI_SUCCESS(AcpiEcSubmitQuery(BusFdo, Ec)))
	    break;
    }
    if (i == ACPI_EC_CLEAR_MAX)
	WARN_(ACPI, "Warning: Maximum of %d stale EC events cleared\n", i);
    else
	INFO_(ACPI, "%d stale EC events cleared\n", i);
}

static VOID AcpiEcEnableEvent(IN PDEVICE_OBJECT BusFdo,
			      IN PACPI_EC Ec)
{
    AcpiEcAcquireLock();
    if (AcpiEcIsStarted(Ec)) {
	if (!TestAndSetBit(EC_FLAGS_QUERY_ENABLED, &Ec->Flags))
	    EcLogDrv("event unblocked");
	/*
	 * Unconditionally invoke this once after enabling the event
	 * handling mechanism to detect the pending events.
	 */
	AdvanceTransaction(Ec, FALSE);
    }
    AcpiEcReleaseLock();

    /* Drain additional events if hardware requires that */
    if (EcFlagsClearOnResume)
	AcpiEcClear(BusFdo, Ec);
}

static VOID AcpiEcDisableEvent(PACPI_EC Ec)
{
    if (TestAndClearBit(EC_FLAGS_QUERY_ENABLED, &Ec->Flags))
	EcLogDrv("event blocked");
}

static BOOLEAN EcTransactionCompleted(PACPI_EC Ec)
{
    AcpiEcAcquireLock();
    if (Ec->CurrentTransaction && (Ec->CurrentTransaction->Flags & ACPI_EC_COMMAND_COMPLETE))
	return TRUE;
    AcpiEcReleaseLock();
    return FALSE;
}

FORCEINLINE VOID EcTransactionTransition(PACPI_EC Ec,
					 ULONG_PTR Flag)
{
    Ec->CurrentTransaction->Flags |= Flag;

    if (Ec->CurrentTransaction->Command != ACPI_EC_COMMAND_QUERY)
	return;

    switch (AcpiEcEventClearing) {
    case ACPI_EC_EVT_TIMING_STATUS:
	if (Flag == ACPI_EC_COMMAND_POLL)
	    AcpiEcCloseEvent(Ec);

	return;

    case ACPI_EC_EVT_TIMING_QUERY:
	if (Flag == ACPI_EC_COMMAND_COMPLETE)
	    AcpiEcCloseEvent(Ec);

	return;

    case ACPI_EC_EVT_TIMING_EVENT:
	if (Flag == ACPI_EC_COMMAND_COMPLETE)
	    AcpiEcCompleteEvent(Ec);
    }
}

static VOID AcpiEcSpuriousInterrupt(PACPI_EC Ec,
				    PEC_TRANSACTION Transaction)
{
    if (Transaction->IrqCount < AcpiEcStormThreshold)
	++Transaction->IrqCount;

    /* Trigger if the threshold is 0 too. */
    if (Transaction->IrqCount == AcpiEcStormThreshold)
	AcpiEcMaskEvents(Ec);
}

static VOID AdvanceTransaction(PACPI_EC Ec,
			       BOOLEAN Interrupt)
{
    PEC_TRANSACTION Curr = Ec->CurrentTransaction;
    BOOLEAN Wakeup = FALSE;
    UCHAR Status;

    EcDbgStm("%s", Interrupt ? "IRQ" : "TASK");

    Status = AcpiEcReadStatus(Ec);

    /*
     * Another IRQ or a guarded polling mode advancement is detected,
     * the next CMD_QUERY submission is then allowed.
     */
    if (!Curr || !(Curr->Flags & ACPI_EC_COMMAND_POLL)) {
	if (AcpiEcEventClearing == ACPI_EC_EVT_TIMING_EVENT &&
	    Ec->EventState == EC_EVENT_COMPLETE)
	    AcpiEcCloseEvent(Ec);

	if (!Curr)
	    goto out;
    }

    if (Curr->Flags & ACPI_EC_COMMAND_POLL) {
	if (Curr->InputLength > Curr->InputIndex) {
	    if (!(Status & ACPI_EC_FLAG_IBF))
		AcpiEcWriteData(Ec, Curr->InputBuffer[Curr->InputIndex++]);
	    else if (Interrupt && !(Status & ACPI_EC_FLAG_SCI))
		AcpiEcSpuriousInterrupt(Ec, Curr);
	} else if (Curr->OutputLength > Curr->OutputIndex) {
	    if (Status & ACPI_EC_FLAG_OBF) {
		Curr->OutputBuffer[Curr->OutputIndex++] = AcpiEcReadData(Ec);
		if (Curr->OutputLength == Curr->OutputIndex) {
		    EcTransactionTransition(Ec, ACPI_EC_COMMAND_COMPLETE);
		    Wakeup = TRUE;
		    if (Curr->Command == ACPI_EC_COMMAND_QUERY)
			EcDbgEvt("Command(%s) completed by hardware",
				 AcpiEcCmdToString(ACPI_EC_COMMAND_QUERY));
		}
	    } else if (Interrupt && !(Status & ACPI_EC_FLAG_SCI)) {
		AcpiEcSpuriousInterrupt(Ec, Curr);
	    }
	} else if (Curr->InputLength == Curr->InputIndex && !(Status & ACPI_EC_FLAG_IBF)) {
	    EcTransactionTransition(Ec, ACPI_EC_COMMAND_COMPLETE);
	    Wakeup = TRUE;
	}
    } else if (!(Status & ACPI_EC_FLAG_IBF)) {
	AcpiEcWriteCmd(Ec, Curr->Command);
	EcTransactionTransition(Ec, ACPI_EC_COMMAND_POLL);
    }

out:
    if (Status & ACPI_EC_FLAG_SCI)
	AcpiEcSubmitEvent(Ec);

    if (Wakeup && Interrupt)
	KeSetEvent(&Ec->CompletionEvent);
}

static VOID StartTransaction(PACPI_EC Ec)
{
    Ec->CurrentTransaction->IrqCount = 0;
    Ec->CurrentTransaction->InputIndex = 0;
    Ec->CurrentTransaction->OutputIndex = 0;
    Ec->CurrentTransaction->Flags = 0;
}

/*
 * Returns TRUE if the transaction has completed, FALSE if the wait has timed out.
 */
static BOOLEAN EcPoll(PACPI_EC Ec)
{
    int Repeat = 5; /* number of command restarts */

    while (Repeat--) {
	LARGE_INTEGER Deadline, CurrentTime;
	KeQuerySystemTime(&Deadline);
	Deadline.QuadPart += (ULONG64)AcpiEcDelay * 10000;
	do {
	    if (EcTransactionCompleted(Ec))
		return TRUE;
	    AcpiEcAcquireLock();
	    AdvanceTransaction(Ec, FALSE);
	    AcpiEcReleaseLock();
	    KeQuerySystemTime(&CurrentTime);
	} while (CurrentTime.QuadPart <= Deadline.QuadPart);
	INFO_(ACPI, "controller reset, restart transaction\n");
	if (Ec->CurrentTransaction) {
	    AcpiEcAcquireLock();
	    StartTransaction(Ec);
	    AcpiEcReleaseLock();
	}
    }
    return FALSE;
}

static ACPI_STATUS AcpiEcTransactionUnlocked(PACPI_EC Ec,
					     PEC_TRANSACTION Transaction)
{
    ACPI_STATUS Ret = AE_OK;

    /* start transaction */
    AcpiEcAcquireLock();
    /* Enable GPE for command processing (IBF=0/OBF=1) */
    if (!AcpiEcSubmitFlushableRequest(Ec)) {
	Ret = AE_BAD_PARAMETER;
	goto unlock;
    }
    EcDbgRef(Ec, "Increase command");
    /* following two actions should be kept atomic */
    Ec->CurrentTransaction = Transaction;
    EcDbgReq("Command(%s) started", AcpiEcCmdToString(Transaction->Command));
    StartTransaction(Ec);
    AcpiEcReleaseLock();

    Ret = EcPoll(Ec) ? AE_OK : AE_TIME;
    if (Ret == AE_TIME) {
	EcDbgReq("Command(%s) timed-out", AcpiEcCmdToString(Transaction->Command));
    }

    AcpiEcAcquireLock();
    if (Transaction->IrqCount == AcpiEcStormThreshold)
	AcpiEcUnmaskEvents(Ec);
    EcDbgReq("Command(%s) stopped", AcpiEcCmdToString(Transaction->Command));
    Ec->CurrentTransaction = NULL;
    /* Disable GPE for command processing (IBF=0/OBF=1) */
    AcpiEcCompleteRequest(Ec);
    EcDbgRef(Ec, "Decrease command");
unlock:
    AcpiEcReleaseLock();
    return Ret;
}

static ACPI_STATUS AcpiEcTransaction(PACPI_EC Ec, PEC_TRANSACTION Transaction)
{
    if (!Ec || (!Transaction) || (Transaction->InputLength && !Transaction->InputBuffer) ||
	(Transaction->OutputLength && !Transaction->OutputBuffer))
	return AE_BAD_PARAMETER;
    if (Transaction->OutputBuffer)
	memset(Transaction->OutputBuffer, 0, Transaction->OutputLength);

    ULONG Glk;
    if (Ec->GlobalLock) {
	ACPI_STATUS Status = AcpiAcquireGlobalLock(ACPI_EC_UDELAY_GLK, &Glk);
	if (ACPI_FAILURE(Status)) {
	    return Status;
	}
    }

    ACPI_STATUS Status = AcpiEcTransactionUnlocked(Ec, Transaction);

    if (Ec->GlobalLock)
	AcpiReleaseGlobalLock(Glk);
    return Status;
}

#define DEFINE_EC_READ_ROUTINE(Name, TransactionRoutine)		\
    static ACPI_STATUS Name(PACPI_EC Ec, UCHAR Address, PUCHAR Data)	\
    {									\
	UCHAR d;							\
	EC_TRANSACTION Transaction = {					\
	    .Command = ACPI_EC_COMMAND_READ,				\
	    .InputBuffer = &Address, .OutputBuffer = &d,		\
	    .InputLength = 1, .OutputLength = 1				\
	};								\
	ACPI_STATUS Result = TransactionRoutine(Ec, &Transaction);	\
	*Data = d;							\
	return Result;							\
    }

DEFINE_EC_READ_ROUTINE(AcpiEcRead, AcpiEcTransaction);
DEFINE_EC_READ_ROUTINE(AcpiEcReadUnlocked, AcpiEcTransactionUnlocked);

ACPI_STATUS EcRead(UCHAR Addr, PUCHAR Data)
{
    if (!AcpiFirstEc)
	return AE_NOT_EXIST;
    return AcpiEcRead(AcpiFirstEc, Addr, Data);
}

#define DEFINE_EC_WRITE_ROUTINE(Name, TransactionRoutine)		\
    static ACPI_STATUS Name(PACPI_EC Ec, UCHAR Address, UCHAR Data)	\
    {									\
	UCHAR InputData[2] = { Address, Data };				\
	EC_TRANSACTION Transaction = {					\
	    .Command = ACPI_EC_COMMAND_WRITE,				\
	    .InputBuffer = InputData, .OutputBuffer = NULL,		\
	    .InputLength = 2, .OutputLength = 0				\
	};								\
	return TransactionRoutine(Ec, &Transaction);			\
    }

DEFINE_EC_WRITE_ROUTINE(AcpiEcWrite, AcpiEcTransaction);
DEFINE_EC_WRITE_ROUTINE(AcpiEcWriteUnlocked, AcpiEcTransactionUnlocked);

ACPI_STATUS EcWrite(UCHAR Addr, UCHAR Val)
{
    if (!AcpiFirstEc)
	return AE_NOT_EXIST;
    return AcpiEcWrite(AcpiFirstEc, Addr, Val);
}

static VOID AcpiEcStart(PACPI_EC Ec, BOOLEAN Resuming)
{
    AcpiEcAcquireLock();
    if (!TestAndSetBit(EC_FLAGS_STARTED, &Ec->Flags)) {
	EcDbgDrv("Starting EC");
	/* Enable GPE for event processing (SCI_EVT=1) */
	if (!Resuming) {
	    AcpiEcSubmitRequest(Ec);
	    EcDbgRef(Ec, "Increase driver");
	}
	EcLogDrv("EC started");
    }
    AcpiEcReleaseLock();
}

static BOOLEAN AcpiEcIsStopped(PACPI_EC Ec)
{
    BOOLEAN Flushed;

    AcpiEcAcquireLock();
    Flushed = AcpiEcIsFlushed(Ec);
    AcpiEcReleaseLock();
    return Flushed;
}

static VOID AcpiEcStop(PACPI_EC Ec, BOOLEAN Suspending)
{
    AcpiEcAcquireLock();
    if (AcpiEcIsStarted(Ec)) {
	EcDbgDrv("Stopping EC");
	SetBit(EC_FLAGS_STOPPED, &Ec->Flags);
	AcpiEcReleaseLock();
	KeWaitForSingleObject(&Ec->CompletionEvent, Executive, KernelMode, FALSE, NULL);
	AcpiEcIsStopped(Ec);
	AcpiEcAcquireLock();
	/* Disable GPE for event processing (SCI_EVT=1) */
	if (!Suspending) {
	    AcpiEcCompleteRequest(Ec);
	    EcDbgRef(Ec, "Decrease driver");
	} else if (!AcpiEcFreezeEvents)
	    AcpiEcDisableEvent(Ec);
	ClearBit(EC_FLAGS_STARTED, &Ec->Flags);
	ClearBit(EC_FLAGS_STOPPED, &Ec->Flags);
	EcLogDrv("EC stopped");
    }
    AcpiEcReleaseLock();
}

/* --------------------------------------------------------------------------
 *                               Event Management
 *  -------------------------------------------------------------------------- */
static PACPI_EC_QUERY_HANDLER AcpiEcGetQueryHandlerByValue(PACPI_EC Ec,
							   UCHAR Value)
{
    LoopOverList(Handler, &Ec->HandlerList, ACPI_EC_QUERY_HANDLER, Node) {
	if (Value == Handler->QueryBit) {
	    return Handler;
	}
    }
    return NULL;
}

static VOID AcpiEcPutQueryHandler(PACPI_EC_QUERY_HANDLER Handler)
{
    ExFreePoolWithTag(Handler, ACPI_TAG);
}

ACPI_STATUS AcpiEcAddQueryHandler(PACPI_EC Ec,
				  UCHAR QueryBit,
				  ACPI_HANDLE Handle,
				  ACPI_EC_QUERY_FUNC Func,
				  PVOID Data)
{
    if (!Handle && !Func)
	return AE_BAD_PARAMETER;

    PACPI_EC_QUERY_HANDLER Handler = ExAllocatePoolWithTag(NonPagedPool,
							   sizeof(ACPI_EC_QUERY_HANDLER),
							   ACPI_TAG);
    if (!Handler)
	return AE_NO_MEMORY;

    Handler->QueryBit = QueryBit;
    Handler->Handle = Handle;
    Handler->Func = Func;
    Handler->Data = Data;
    InsertTailList(&Ec->HandlerList, &Handler->Node);
    return AE_OK;
}

static VOID AcpiEcRemoveQueryHandlers(PACPI_EC Ec,
				      BOOLEAN RemoveAll,
				      UCHAR QueryBit)
{
    LoopOverList(Handler, &Ec->HandlerList, ACPI_EC_QUERY_HANDLER, Node) {
	/*
	 * When RemoveAll is FALSE, only remove custom query handlers
	 * which have Handler->Func set. This is done to preserve query
	 * handlers discovered thru ACPI, as they should continue handling
	 * EC queries.
	 */
	if (RemoveAll || (Handler->Func && Handler->QueryBit == QueryBit)) {
	    RemoveEntryList(&Handler->Node);
	    AcpiEcPutQueryHandler(Handler);
	}
    }
}

VOID AcpiEcRemoveQueryHandler(PACPI_EC Ec, UCHAR QueryBit)
{
    AcpiEcRemoveQueryHandlers(Ec, FALSE, QueryBit);
}

static NTAPI VOID AcpiEcProcessEvent(IN PACPI_EC_QUERY Query)
{
    PACPI_EC_QUERY_HANDLER Handler = Query->Handler;
    PACPI_EC Ec = Query->Ec;

    EcDbgEvt("Query(0x%02x) started", Handler->QueryBit);

    if (Handler->Func)
	Handler->Func(Handler->Data);
    else if (Handler->Handle)
	AcpiEvaluateObject(Handler->Handle, NULL, NULL, NULL);

    EcDbgEvt("Query(0x%02x) stopped", Handler->QueryBit);

    AcpiEcAcquireLock();
    Ec->QueriesInProgress--;
    AcpiEcReleaseLock();

    AcpiEcPutQueryHandler(Handler);
    ExFreePoolWithTag(Query, ACPI_TAG);
}

static PACPI_EC_QUERY AcpiEcCreateQuery(IN PDEVICE_OBJECT BusFdo,
					IN PACPI_EC Ec,
					IN PUCHAR pVal)
{
    PACPI_EC_QUERY Query = ExAllocatePoolWithTag(NonPagedPool,
						 sizeof(ACPI_EC_QUERY),
						 ACPI_TAG);
    if (!Query)
	return NULL;

    PEC_TRANSACTION Transaction = &Query->Transaction;
    Transaction->Command = ACPI_EC_COMMAND_QUERY;
    Transaction->OutputBuffer = pVal;
    Transaction->OutputLength = 1;
    Query->Ec = Ec;
    return Query;
}

static ACPI_STATUS AcpiEcSubmitQuery(IN PDEVICE_OBJECT BusFdo,
				     IN PACPI_EC Ec)
{
    PAGED_CODE();
    UCHAR Value = 0;

    PACPI_EC_QUERY Query = AcpiEcCreateQuery(BusFdo, Ec, &Value);
    if (!Query)
	return AE_NO_MEMORY;

    /*
     * Query the EC to find out which _Qxx method we need to evaluate.
     * Note that successful completion of the query causes the ACPI_EC_SCI
     * bit to be cleared (and thus clearing the interrupt source).
     */
    ACPI_STATUS Status = AcpiEcTransaction(Ec, &Query->Transaction);
    if (!ACPI_SUCCESS(Status))
	goto Err;

    if (!Value) {
	Status = AE_NOT_EXIST;
	goto Err;
    }

    Query->Handler = AcpiEcGetQueryHandlerByValue(Ec, Value);
    if (!Query->Handler) {
	Status = AE_NOT_EXIST;
	goto Err;
    }

    /*
     * It is reported that _Qxx are evaluated in a parallel way on Windows:
     * https://bugzilla.kernel.org/show_bug.cgi?id=94411
     *
     * Put this log entry before IoQueueWorkItem() to make it appear in the log
     * before any other messages emitted during workqueue handling.
     */
    EcDbgEvt("Query(0x%02x) scheduled", Value);

    AcpiEcAcquireLock();

    Ec->QueriesInProgress++;
    AcpiEcProcessEvent(Query);

    AcpiEcReleaseLock();

    return AE_OK;

Err:
    ExFreePoolWithTag(Query, ACPI_TAG);
    return Status;
}

static NTAPI VOID AcpiEcEventHandler(IN PDEVICE_OBJECT BusFdo,
				     IN PVOID Context)
{
    PACPI_EC Ec = Context;

    EcDbgEvt("Event started");

    AcpiEcAcquireLock();

    while (Ec->EventsToProcess) {
	AcpiEcReleaseLock();

	AcpiEcSubmitQuery(BusFdo, Ec);

	AcpiEcAcquireLock();

	Ec->EventsToProcess--;
    }

    /*
     * Before exit, make sure that the it will be possible to queue up the
     * event handling work again regardless of whether or not the query
     * queued up above is processed successfully.
     */
    if (AcpiEcEventClearing == ACPI_EC_EVT_TIMING_EVENT) {
	AcpiEcCompleteEvent(Ec);

	EcDbgEvt("Event stopped");

	/* Take care of SCI_EVT unless someone else is doing that. */
	if (!EcTransactionCompleted(Ec) && !Ec->CurrentTransaction)
	    AdvanceTransaction(Ec, FALSE);
    } else {
	AcpiEcCloseEvent(Ec);

	EcDbgEvt("Event stopped");
    }

    Ec->EventsInProgress--;

    AcpiEcReleaseLock();
}

static VOID ClearGpeAndAdvanceTransaction(PACPI_EC Ec, BOOLEAN Interrupt)
{
    /*
     * Clear GPE_STS upfront to allow subsequent hardware GPE_STS 0->1
     * changes to always trigger a GPE interrupt.
     *
     * GPE STS is a W1C register, which means:
     *
     * 1. Software can clear it without worrying about clearing the other
     *    GPEs' STS bits when the hardware sets them in parallel.
     *
     * 2. As long as software can ensure only clearing it when it is set,
     *    hardware won't set it in parallel.
     */
    if (Ec->Gpe >= 0 && AcpiEcIsGpeStatusSet(Ec))
	AcpiClearGpe(NULL, Ec->Gpe);

    AdvanceTransaction(Ec, TRUE);
}

static VOID AcpiEcHandleInterrupt(PACPI_EC Ec)
{
    AcpiEcAcquireLock();

    ClearGpeAndAdvanceTransaction(Ec, TRUE);

    AcpiEcReleaseLock();
}

static ULONG AcpiEcGpeHandler(ACPI_HANDLE GpeDevice,
			      ULONG GpeNumber, PVOID Data)
{
    EcDbgGpe("Handling GPE interrupt (GPE device %p GpeNumber %d Data %p)\n",
	     GpeDevice, GpeNumber, Data);
    AcpiEcHandleInterrupt(Data);
    return ACPI_INTERRUPT_HANDLED;
}

/* --------------------------------------------------------------------------
 *                           Address Space Management
 * -------------------------------------------------------------------------- */

static ACPI_STATUS AcpiEcAddressSpaceHandler(ULONG Function,
					     ACPI_PHYSICAL_ADDRESS Address,
					     ULONG Bits,
					     PULONG64 Value64,
					     PVOID HandlerContext,
					     PVOID RegionContext)
{
    PACPI_EC Ec = HandlerContext;
    PUCHAR Value = (PUCHAR)Value64;
    ULONG Glk;

    if ((Address > 0xFF) || !Value || !HandlerContext)
	return AE_BAD_PARAMETER;

    if (Function != ACPI_READ && Function != ACPI_WRITE)
	return AE_BAD_PARAMETER;

    if (Ec->GlobalLock) {
	ACPI_STATUS Status = AcpiAcquireGlobalLock(ACPI_EC_UDELAY_GLK, &Glk);
	if (ACPI_FAILURE(Status)) {
	    return Status;
	}
    }

    ACPI_STATUS Status = AE_OK;
    for (int i = 0; i < Bits / 8; ++i, ++Address, ++Value)
	Status = (Function == ACPI_READ) ? AcpiEcReadUnlocked(Ec, Address, Value) :
	    AcpiEcWriteUnlocked(Ec, Address, *Value);

    if (Ec->GlobalLock)
	AcpiReleaseGlobalLock(Glk);

    return Status;
}

/* --------------------------------------------------------------------------
 *                             Driver Interface
 * -------------------------------------------------------------------------- */

static ACPI_STATUS EcParseIoPorts(ACPI_RESOURCE *Resource,
				  PVOID context);

static VOID AcpiEcFree(PACPI_EC Ec)
{
    if (AcpiFirstEc == Ec)
	AcpiFirstEc = NULL;
    if (AcpiBootEc == Ec)
	AcpiBootEc = NULL;
    ExFreePoolWithTag(Ec, ACPI_TAG);
}

static PACPI_EC AcpiEcAlloc(IN PDEVICE_OBJECT BusFdo)
{
    PACPI_EC Ec = ExAllocatePoolWithTag(NonPagedPool, sizeof(ACPI_EC), ACPI_TAG);

    if (!Ec)
	return NULL;
    KeInitializeEvent(&Ec->CompletionEvent, SynchronizationEvent, FALSE);
    InitializeListHead(&Ec->HandlerList);
    IoInitializeWorkItem(BusFdo, &Ec->WorkItem);
    Ec->Gpe = -1;
    return Ec;
}

static ACPI_STATUS AcpiEcRegisterQueryMethods(ACPI_HANDLE Handle,
					      ULONG Level,
					      PVOID Context,
					      PPVOID ReturnValue)
{
    CHAR NodeName[5];
    ACPI_BUFFER Buffer = { sizeof(NodeName), NodeName };
    PACPI_EC Ec = Context;
    ULONG Value = 0;
    ACPI_STATUS Status;

    Status = AcpiGetName(Handle, ACPI_SINGLE_NAME, &Buffer);

    if (ACPI_SUCCESS(Status) && NodeName[0] == '_' && NodeName[1] == 'Q' &&
	NT_SUCCESS(RtlCharToInteger(&NodeName[2], 16, &Value)))
	AcpiEcAddQueryHandler(Ec, Value, Handle, NULL, NULL);
    return AE_OK;
}

static ACPI_STATUS EcParseDevice(ACPI_HANDLE Handle,
				 ULONG Level,
				 PVOID Context,
				 PPVOID RetVal)
{
    ACPI_STATUS Status;
    ULONG64 Tmp = 0;
    PACPI_EC Ec = Context;

    /* clear addr values, EcParseIoPorts depend on it */
    Ec->CommandAddress = Ec->DataAddress = 0;

    Status = AcpiWalkResources(Handle, METHOD_NAME__CRS,
			       EcParseIoPorts, Ec);
    if (ACPI_FAILURE(Status))
	return Status;
    if (Ec->DataAddress == 0 || Ec->CommandAddress == 0)
	return AE_OK;

    /* Get GPE bit assignment (EC events). */
    /* TODO: Add support for _GPE returning a package */
    Status = AcpiEvaluateInteger(Handle, "_GPE", NULL, &Tmp);
    if (ACPI_SUCCESS(Status))
	Ec->Gpe = Tmp;
    /*
     * Errors are non-fatal, allowing for ACPI Reduced Hardware
     * platforms which use GpioInt instead of GPE.
     */

    /* Use the global lock for all EC transactions? */
    Tmp = 0;
    AcpiEvaluateInteger(Handle, "_GLK", NULL, &Tmp);
    Ec->GlobalLock = Tmp;
    Ec->Handle = Handle;
    return AE_CTRL_TERMINATE;
}

static BOOLEAN InstallGpeEventHandler(PACPI_EC Ec)
{
    ACPI_STATUS Status;

    Status = AcpiInstallGpeRawHandler(NULL, Ec->Gpe,
				      ACPI_GPE_EDGE_TRIGGERED,
				      &AcpiEcGpeHandler, Ec);
    if (ACPI_FAILURE(Status))
	return FALSE;

    if (IsBitSet(EC_FLAGS_STARTED, &Ec->Flags) && Ec->ReferenceCount >= 1)
	AcpiEcEnableGpe(Ec, TRUE);

    return TRUE;
}

/**
 * AcpiEcInstallHandlers - Install service callbacks and register query methods.
 * @DeviceObject: Device object of the ACPI bus
 * @Ec: Target EC.
 * @Device: ACPI device object corresponding to @Ec.
 * @CallReg: If _REG should be called to notify OpRegion availability
 *
 * Install a handler for the EC address space type unless it has been installed
 * already.  If @Device is not NULL, also look for EC query methods in the
 * namespace and register them, and install an event (either GPE or GPIO IRQ)
 * handler for the EC, if possible.
 *
 * Return:
 * AE_NOT_FOUND if the address space handler cannot be installed, which means
 *  "unable to handle transactions",
 * -EPROBE_DEFER if GPIO IRQ acquisition needs to be deferred,
 * or 0 (success) otherwise.
 */
static ACPI_STATUS AcpiEcInstallHandlers(IN PDEVICE_OBJECT BusFdo,
					 IN PACPI_EC Ec,
					 IN PACPI_DEVICE Device,
					 IN BOOLEAN CallReg)
{
    ACPI_STATUS Status;

    AcpiEcStart(Ec, FALSE);

    if (!IsBitSet(EC_FLAGS_EC_HANDLER_INSTALLED, &Ec->Flags)) {
	Status = AcpiInstallAddressSpaceHandlerNoReg(Ec->Handle,
						     ACPI_ADR_SPACE_EC,
						     &AcpiEcAddressSpaceHandler,
						     NULL, Ec);
	if (ACPI_FAILURE(Status)) {
	    AcpiEcStop(Ec, FALSE);
	    return AE_NOT_FOUND;
	}
	SetBit(EC_FLAGS_EC_HANDLER_INSTALLED, &Ec->Flags);
	Ec->AddressSpaceHandlerHolder = Ec->Handle;
    }

    if (CallReg && !IsBitSet(EC_FLAGS_EC_REG_CALLED, &Ec->Flags)) {
	AcpiExecuteRegMethods(Ec->Handle, ACPI_ADR_SPACE_EC);
	SetBit(EC_FLAGS_EC_REG_CALLED, &Ec->Flags);
    }

    if (!Device)
	return AE_OK;

    if (!IsBitSet(EC_FLAGS_QUERY_METHODS_INSTALLED, &Ec->Flags)) {
	/* Find and register all query methods */
	AcpiWalkNamespace(ACPI_TYPE_METHOD, Ec->Handle, 1,
			  AcpiEcRegisterQueryMethods,
			  NULL, Ec, NULL);
	SetBit(EC_FLAGS_QUERY_METHODS_INSTALLED, &Ec->Flags);
    }
    if (!IsBitSet(EC_FLAGS_EVENT_HANDLER_INSTALLED, &Ec->Flags)) {
	BOOLEAN Ready = FALSE;

	if (Ec->Gpe >= 0)
	    Ready = InstallGpeEventHandler(Ec);

	if (Ready) {
	    SetBit(EC_FLAGS_EVENT_HANDLER_INSTALLED, &Ec->Flags);
	}
	/*
	 * Failures to install an event handler are not fatal, because
	 * the EC can be polled for events.
	 */
    }
    /* EC is fully operational, allow queries */
    AcpiEcEnableEvent(BusFdo, Ec);

    return AE_OK;
}

static VOID EcRemoveHandlers(PACPI_EC Ec)
{
    if (IsBitSet(EC_FLAGS_EC_HANDLER_INSTALLED, &Ec->Flags)) {
	if (ACPI_FAILURE(AcpiRemoveAddressSpaceHandler(Ec->AddressSpaceHandlerHolder,
						       ACPI_ADR_SPACE_EC,
						       &AcpiEcAddressSpaceHandler)))
	    ERR_(ACPI, "failed to remove space handler\n");
	ClearBit(EC_FLAGS_EC_HANDLER_INSTALLED, &Ec->Flags);
    }

    /*
     * Stops handling the EC transactions after removing the operation
     * region handler. This is required because _REG(DISCONNECT)
     * invoked during the removal can result in new EC transactions.
     *
     * Flushes the EC requests and thus disables the GPE before
     * removing the GPE handler. This is required by the current ACPICA
     * GPE core. ACPICA GPE core will automatically disable a GPE when
     * it is indicated but there is no way to handle it. So the drivers
     * must disable the GPEs prior to removing the GPE handlers.
     */
    AcpiEcStop(Ec, FALSE);

    if (IsBitSet(EC_FLAGS_EVENT_HANDLER_INSTALLED, &Ec->Flags)) {
	if (Ec->Gpe >= 0 &&
	    ACPI_FAILURE(AcpiRemoveGpeHandler(NULL, Ec->Gpe,
					      &AcpiEcGpeHandler)))
	    ERR_(ACPI, "failed to remove gpe handler\n");

	ClearBit(EC_FLAGS_EVENT_HANDLER_INSTALLED, &Ec->Flags);
    }
    if (IsBitSet(EC_FLAGS_QUERY_METHODS_INSTALLED, &Ec->Flags)) {
	AcpiEcRemoveQueryHandlers(Ec, TRUE, 0);
	ClearBit(EC_FLAGS_QUERY_METHODS_INSTALLED, &Ec->Flags);
    }
}

static ACPI_STATUS AcpiEcSetup(IN PDEVICE_OBJECT BusFdo,
			       IN PACPI_EC Ec,
			       IN PACPI_DEVICE Device,
			       IN BOOLEAN CallReg)
{
    if (!RequestRegion(Ec->DataAddress, 1, "EC data")) {
	WARN_(ACPI, "Could not request EC data io port 0x%zx", Ec->DataAddress);
	return AE_ERROR;
    }

    if (!RequestRegion(Ec->CommandAddress, 1, "EC cmd")) {
	WARN_(ACPI, "Could not request EC cmd io port 0x%zx", Ec->CommandAddress);
	return AE_ERROR;
    }

    ACPI_STATUS Ret = AcpiEcInstallHandlers(BusFdo, Ec, Device, CallReg);
    if (!ACPI_SUCCESS(Ret))
	return Ret;

    /* First EC capable of handling transactions */
    if (!AcpiFirstEc)
	AcpiFirstEc = Ec;

    INFO_(ACPI, "EC_CMD/EC_SC=0x%zx, EC_DATA=0x%zx\n", Ec->CommandAddress,
	  Ec->DataAddress);

    if (IsBitSet(EC_FLAGS_EVENT_HANDLER_INSTALLED, &Ec->Flags)) {
	if (Ec->Gpe >= 0)
	    INFO_(ACPI, "GPE=0x%x\n", Ec->Gpe);
    }

    return Ret;
}

static ACPI_STATUS AcpiEcAdd(IN PDEVICE_OBJECT BusFdo,
			     IN PACPI_DEVICE Device)
{
    strcpy(ACPI_DEVICE_NAME(Device), ACPI_EC_DEVICE_NAME);
    strcpy(ACPI_DEVICE_CLASS(Device), ACPI_EC_CLASS);

    ACPI_STATUS Ret;
    PACPI_EC Ec;
    if (AcpiBootEc && (AcpiBootEc->Handle == Device->Handle ||
		       !strcmp(ACPI_DEVICE_HID(Device), ACPI_ECDT_HID))) {
	/* Fast path: this device corresponds to the boot EC. */
	Ec = AcpiBootEc;
    } else {
	Ec = AcpiEcAlloc(BusFdo);
	if (!Ec)
	    return AE_NO_MEMORY;

	ACPI_STATUS Status = EcParseDevice(Device->Handle, 0, Ec, NULL);
	if (Status != AE_CTRL_TERMINATE) {
	    Ret = AE_BAD_PARAMETER;
	    goto Err;
	}

	if (AcpiBootEc && Ec->CommandAddress == AcpiBootEc->CommandAddress &&
	    Ec->DataAddress == AcpiBootEc->DataAddress) {
	    /*
	     * Trust PNP0C09 namespace location rather than ECDT ID.
	     * But trust ECDT GPE rather than _GPE because of ASUS
	     * quirks. So do not change AcpiBootEc->gpe to ec->gpe,
	     * except when the TRUST_DSDT_GPE quirk is set.
	     */
	    AcpiBootEc->Handle = Ec->Handle;

	    if (EcFlagsTrustDsdtGpe)
		AcpiBootEc->Gpe = Ec->Gpe;

	    ACPI_HANDLE_DEBUG(Ec->Handle, "duplicated.\n");
	    AcpiEcFree(Ec);
	    Ec = AcpiBootEc;
	}
    }

    Ret = AcpiEcSetup(BusFdo, Ec, Device, TRUE);
    if (!ACPI_SUCCESS(Ret))
	goto Err;

    if (Ec == AcpiBootEc)
	ACPI_HANDLE_INFO(AcpiBootEc->Handle,
			 "Boot %s EC initialization complete\n",
			 AcpiBootEcIsEcdt ? "ECDT" : "DSDT");

    ACPI_HANDLE_INFO(Ec->Handle,
		     "EC: Used to handle transactions and events\n");

    Device->DriverData = Ec;

    ACPI_HANDLE_DEBUG(Ec->Handle, "enumerated.\n");
    return AE_OK;

Err:
    if (Ec != AcpiBootEc)
	AcpiEcFree(Ec);

    return Ret;
}

static ACPI_STATUS AcpiEcRemove(PACPI_DEVICE Device, ACPI_BUS_REMOVAL_TYPE Type)
{
    PACPI_EC Ec;

    if (!Device)
	return AE_NOT_EXIST;

    Ec = ACPI_BUSMGR_COMPONENT_DATA(Device);
    Device->DriverData = NULL;
    if (Ec != AcpiBootEc) {
	EcRemoveHandlers(Ec);
	AcpiEcFree(Ec);
    }
    return AE_OK;
}

static ACPI_STATUS EcParseIoPorts(ACPI_RESOURCE *Resource,
				  PVOID Context)
{
    PACPI_EC Ec = Context;

    if (Resource->Type != ACPI_RESOURCE_TYPE_IO)
	return AE_OK;

    /*
     * The first address region returned is the data port, and
     * the second address region returned is the status/command
     * port.
     */
    if (Ec->DataAddress == 0)
	Ec->DataAddress = Resource->Data.Io.Minimum;
    else if (Ec->CommandAddress == 0)
	Ec->CommandAddress = Resource->Data.Io.Minimum;
    else
	return AE_CTRL_TERMINATE;

    return AE_OK;
}

/*
 * This function is not Windows-compatible as Windows never enumerates the
 * namespace EC before the main ACPI device enumeration process. It is
 * retained for historical reason and will be deprecated in the future.
 */
VOID AcpiEcProbeDsdt(IN PDEVICE_OBJECT BusFdo)
{
    PACPI_EC Ec;
    ACPI_STATUS Status;

    /*
     * If a platform has ECDT, there is no need to proceed as the
     * following probe is not a part of the ACPI device enumeration,
     * executing _STA is not safe, and thus this probe may risk of
     * picking up an invalid EC device.
     */
    if (AcpiBootEc)
	return;

    Ec = AcpiEcAlloc(BusFdo);
    if (!Ec)
	return;

    /*
     * At this point, the namespace is initialized, so start to find
     * the namespace objects.
     */
    Status = AcpiGetDevices(EC_DEVICE_ID, EcParseDevice, Ec, NULL);
    if (ACPI_FAILURE(Status) || !Ec->Handle) {
	AcpiEcFree(Ec);
	return;
    }

    /*
     * When the DSDT EC is available, always re-configure boot EC to
     * have _REG evaluated. _REG can only be evaluated after the
     * namespace initialization.
     * At this point, the GPE is not fully initialized, so do not
     * handle the events.
     */
    ACPI_STATUS Ret = AcpiEcSetup(BusFdo, Ec, NULL, TRUE);
    if (!ACPI_SUCCESS(Ret)) {
	AcpiEcFree(Ec);
	return;
    }

    AcpiBootEc = Ec;

    ACPI_HANDLE_INFO(Ec->Handle,
		     "Boot DSDT EC used to handle transactions\n");
}

/*
 * AcpiEcStartEcdt - Finalize the boot ECDT EC initialization.
 *
 * First, look for an ACPI handle for the boot ECDT EC if AcpiEcAdd() has not
 * found a matching object in the namespace.
 *
 * Next, in case the DSDT EC is not functioning, it is still necessary to
 * provide a functional ECDT EC to handle events, so add an extra device object
 * to represent it (see https://bugzilla.kernel.org/show_bug.cgi?id=115021).
 *
 * This is useful on platforms with valid ECDT and invalid DSDT EC settings,
 * like ASUS X550ZE (see https://bugzilla.kernel.org/show_bug.cgi?id=196847).
 */
static VOID AcpiEcStartEcdt(VOID)
{
    ACPI_TABLE_ECDT *EcdtPtr;
    ACPI_HANDLE Handle;
    ACPI_STATUS Status;

    /* Bail out if a matching EC has been found in the namespace. */
    if (!AcpiBootEc || AcpiBootEc->Handle != ACPI_ROOT_OBJECT)
	return;

    /* Look up the object pointed to from the ECDT in the namespace. */
    Status = AcpiGetTable(ACPI_SIG_ECDT, 1,
			  (ACPI_TABLE_HEADER **)&EcdtPtr);
    if (ACPI_FAILURE(Status))
	return;

    Status = AcpiGetHandle(NULL, (PCSTR)EcdtPtr->Id, &Handle);
    if (ACPI_SUCCESS(Status)) {
	AcpiBootEc->Handle = Handle;
    }

    AcpiPutTable((ACPI_TABLE_HEADER *)EcdtPtr);
}

VOID AcpiEcProbeEcdt(IN PDEVICE_OBJECT BusFdo)
{
    ACPI_TABLE_ECDT *EcdtPtr;
    PACPI_EC Ec;
    ACPI_STATUS Status;
    int Ret;

    /* Generate a boot ec context. */
    Status = AcpiGetTable(ACPI_SIG_ECDT, 1,
			  (ACPI_TABLE_HEADER **)&EcdtPtr);
    if (ACPI_FAILURE(Status))
	return;

    if (!EcdtPtr->Control.Address || !EcdtPtr->Data.Address) {
	/*
	 * Asus X50GL:
	 * https://bugzilla.kernel.org/show_bug.cgi?id=11880
	 */
	goto out;
    }

    Ec = AcpiEcAlloc(BusFdo);
    if (!Ec)
	goto out;

    if (EcFlagsCorrectEcdt) {
	Ec->CommandAddress = EcdtPtr->Data.Address;
	Ec->DataAddress = EcdtPtr->Control.Address;
    } else {
	Ec->CommandAddress = EcdtPtr->Control.Address;
	Ec->DataAddress = EcdtPtr->Data.Address;
    }

    /*
     * Ignore the GPE value on Reduced Hardware platforms.
     * Some products have this set to an erroneous value.
     */
    if (!AcpiGbl_ReducedHardware)
	Ec->Gpe = EcdtPtr->Gpe;

    Ec->Handle = ACPI_ROOT_OBJECT;

    /*
     * At this point, the namespace is not initialized, so do not find
     * the namespace objects, or handle the events.
     */
    Ret = AcpiEcSetup(BusFdo, Ec, NULL, FALSE);
    if (Ret) {
	AcpiEcFree(Ec);
	goto out;
    }

    AcpiBootEc = Ec;
    AcpiBootEcIsEcdt = TRUE;

    INFO_(ACPI, "Boot ECDT EC used to handle transactions\n");

out:
    AcpiPutTable((ACPI_TABLE_HEADER *)EcdtPtr);
}

static ACPI_BUSMGR_COMPONENT AcpiEcDriver = {
    .Name = ACPI_EC_DRIVER_NAME,
    .Class = ACPI_EC_CLASS,
    .Ids = EC_DEVICE_ID,
    .Ops = {
	.Add = AcpiEcAdd,
	.Remove = AcpiEcRemove,
    },
};

VOID AcpiEcInit(IN PDEVICE_OBJECT BusFdo)
{
    AcpiBusRegisterDriver(BusFdo, &AcpiEcDriver);
    AcpiEcStartEcdt();
}
