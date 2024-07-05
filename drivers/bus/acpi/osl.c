/*******************************************************************************
 *                                                                              *
 * ACPI Component Architecture Operating System Layer (OSL) for ReactOS         *
 *                                                                              *
 *******************************************************************************/

#include "precomp.h"
#include <pci.h>

typedef struct _ACPI_ISR_CONTEXT {
    ACPI_OSD_HANDLER Handler;
    PVOID Context;
    ULONG IrqNumber;
} ACPI_ISR_CONTEXT, *PACPI_ISR_CONTEXT;

static PDEVICE_OBJECT AcpiBusFdo;
static ACPI_PHYSICAL_ADDRESS AcpiRootSystemTable;
static BOOLEAN AcpiRootSystemTableIsLegacy;
static PKINTERRUPT AcpiInterrupt;
static ACPI_ISR_CONTEXT AcpiIsrContext;

ACPI_STATUS AcpiOsInitialize(VOID)
{
    DPRINT("AcpiOsInitialize called\n");

#ifndef NDEBUG
    /* Verboseness level of the acpica core */
    AcpiDbgLevel = ACPI_LV_INIT | ACPI_LV_DEBUG_OBJECT | ACPI_LV_INFO;
    AcpiDbgLayer = 0xFFFFFFFF;
#endif

    return AE_OK;
}

ACPI_STATUS AcpiOsTerminate(VOID)
{
    DPRINT("AcpiOsTerminate() called\n");

    return AE_OK;
}

VOID AcpiOsSetBusFdo(IN PDEVICE_OBJECT Fdo)
{
    AcpiBusFdo = Fdo;
}

PDEVICE_OBJECT AcpiOsGetBusFdo()
{
    return AcpiBusFdo;
}

VOID AcpiOsSetRootSystemTable(ACPI_PHYSICAL_ADDRESS Rsdt,
			      ULONG Length)
{
    DPRINT("Setting XSDT to 0x%llx, Length 0x%x\n", Rsdt, Length);
    assert(Rsdt);
    assert(Length);
    AcpiRootSystemTable = Rsdt;
    AcpiRootSystemTableIsLegacy = Length == 4;
}

ACPI_PHYSICAL_ADDRESS AcpiOsGetRootSystemTable()
{
    DPRINT("AcpiOsGetRootSystemTable\n");

    return AcpiRootSystemTable;
}

INT AcpiOsIsRootSystemTableLegacy()
{
    return AcpiRootSystemTableIsLegacy;
}

ACPI_STATUS AcpiOsPredefinedOverride(const ACPI_PREDEFINED_NAMES *PredefinedObject,
				     ACPI_STRING *NewValue)
{
    if (!PredefinedObject || !NewValue) {
	DPRINT1("Invalid parameter\n");
	return AE_BAD_PARAMETER;
    }

    /* No override */
    *NewValue = NULL;

    return AE_OK;
}

ACPI_STATUS AcpiOsTableOverride(ACPI_TABLE_HEADER *ExistingTable,
				ACPI_TABLE_HEADER **NewTable)
{
    if (!ExistingTable || !NewTable) {
	DPRINT1("Invalid parameter\n");
	return AE_BAD_PARAMETER;
    }

    /* No override */
    *NewTable = NULL;

    return AE_OK;
}

ACPI_STATUS AcpiOsPhysicalTableOverride(ACPI_TABLE_HEADER *ExistingTable,
					ACPI_PHYSICAL_ADDRESS *NewAddress,
					UINT32 *NewTableLength)
{
    if (!ExistingTable || !NewAddress || !NewTableLength) {
	DPRINT1("Invalid parameter\n");
	return AE_BAD_PARAMETER;
    }

    /* No override */
    *NewAddress = 0;
    *NewTableLength = 0;

    return AE_OK;
}

PVOID AcpiOsMapMemory(ACPI_PHYSICAL_ADDRESS Phys, ACPI_SIZE Length)
{
    DPRINT("AcpiOsMapMemory(phys 0x%llx  size 0x%zX)\n", Phys, Length);

    PHYSICAL_ADDRESS Address = { .QuadPart = (ULONG)Phys };
    PVOID Ptr = MmMapIoSpace(Address, Length, MmNonCached);
    if (!Ptr) {
	DPRINT1("Mapping failed\n");
    }

    return Ptr;
}

VOID AcpiOsUnmapMemory(PVOID Virt, ACPI_SIZE Length)
{
    DPRINT("AcpiOsUnmapMemory(virt %p  size 0x%zX)\n", Virt, Length);

    ASSERT(Virt);

    MmUnmapIoSpace(Virt, Length);
}

ACPI_STATUS AcpiOsGetPhysicalAddress(PVOID LogicalAddress,
				     ACPI_PHYSICAL_ADDRESS *PhysicalAddress)
{
    PHYSICAL_ADDRESS PhysAddr;

    if (!LogicalAddress || !PhysicalAddress) {
	DPRINT1("Bad parameter\n");
	return AE_BAD_PARAMETER;
    }

    PhysAddr = MmGetPhysicalAddress(LogicalAddress);

    *PhysicalAddress = (ACPI_PHYSICAL_ADDRESS)PhysAddr.QuadPart;

    return AE_OK;
}

PVOID AcpiOsAllocate(ACPI_SIZE Size)
{
    return ExAllocatePoolWithTag(Size, ACPI_TAG);
}

VOID AcpiOsFree(PVOID Ptr)
{
    if (!Ptr)
	DPRINT1("Attempt to free null pointer!!!\n");
    ExFreePoolWithTag(Ptr, ACPI_TAG);
}

static volatile UCHAR Probe;

BOOLEAN AcpiOsReadable(PVOID Memory, ACPI_SIZE Length)
{
    __try {
	for (ACPI_SIZE i = 0; i < Length; i++) {
	    Probe = ((PUCHAR)Memory)[i];
	}
    } __except(EXCEPTION_EXECUTE_HANDLER) {
	return FALSE;
    }

    return TRUE;
}

BOOLEAN AcpiOsWritable(PVOID Memory, ACPI_SIZE Length)
{
    __try {
	for (ACPI_SIZE i = 0; i < Length; i++) {
	    Probe = ((PUCHAR)Memory)[i];
	    ((PUCHAR)Memory)[i] = Probe;
	}
    } __except(EXCEPTION_EXECUTE_HANDLER) {
	return FALSE;
    }

    return TRUE;
}

ACPI_THREAD_ID AcpiOsGetThreadId(VOID)
{
    /* Thread ID must be non-zero. Since we are always in the main thread
     * (this routine is never called by the ACPI ISR), just return one. */
    return 1;
}

typedef struct _ACPI_WORK_ITEM_CONTEXT {
    PIO_WORKITEM WorkItem;
    ACPI_OSD_EXEC_CALLBACK Function;
    PVOID Context;
} ACPI_WORK_ITEM_CONTEXT, *PACPI_WORK_ITEM_CONTEXT;

static NTAPI VOID AcpiWorkItemRoutine(IN PDEVICE_OBJECT DeviceObject,
				      IN OPTIONAL PVOID Ctx)
{
    PACPI_WORK_ITEM_CONTEXT Context = Ctx;
    Context->Function(Context->Context);
    IoFreeWorkItem(Context->WorkItem);
    ExFreePoolWithTag(Context, ACPI_TAG);
}

ACPI_STATUS AcpiOsExecute(ACPI_EXECUTE_TYPE Type,
			  ACPI_OSD_EXEC_CALLBACK Function,
			  PVOID Context)
{
    DPRINT("AcpiOsExecute\n");
    PACPI_WORK_ITEM_CONTEXT Ctx = ExAllocatePoolWithTag(sizeof(ACPI_WORK_ITEM_CONTEXT),
							ACPI_TAG);
    if (!Ctx) {
	return AE_NO_MEMORY;
    }
    Ctx->WorkItem = IoAllocateWorkItem(AcpiBusFdo);
    if (!Ctx->WorkItem) {
	ExFreePoolWithTag(Ctx, ACPI_TAG);
	return AE_NO_MEMORY;
    }
    Ctx->Function = Function;
    Ctx->Context = Context;
    IoQueueWorkItem(Ctx->WorkItem, AcpiWorkItemRoutine, DelayedWorkQueue, Ctx);
    return AE_OK;
}

VOID AcpiOsSleep(UINT64 Milliseconds)
{
    DPRINT("AcpiOsSleep %llu\n", Milliseconds);
    LARGE_INTEGER Delay = {
	/* Unit is 100ns. */
	.QuadPart = Milliseconds * 1000 * 10
    };
    KeDelayExecutionThread(FALSE, &Delay);
}

VOID AcpiOsStall(UINT32 Microseconds)
{
    DPRINT("AcpiOsStall %d\n", Microseconds);
    KeStallExecutionProcessor(Microseconds);
}

ACPI_STATUS AcpiOsWaitSemaphore(ACPI_SEMAPHORE Handle,
				UINT32 Units,
				UINT16 Timeout)
{
    if (AcpiInterrupt) {
	IoAcquireInterruptMutex(AcpiInterrupt);
    }
    return AE_OK;
}

ACPI_STATUS AcpiOsSignalSemaphore(ACPI_SEMAPHORE Handle,
				  UINT32 Units)
{
    if (AcpiInterrupt) {
	IoReleaseInterruptMutex(AcpiInterrupt);
    }
    return AE_OK;
}

ACPI_CPU_FLAGS AcpiOsAcquireLock(ACPI_SPINLOCK Handle)
{
    if (AcpiInterrupt) {
	IoAcquireInterruptMutex(AcpiInterrupt);
    }
    return 0;
}

VOID AcpiOsReleaseLock(ACPI_SPINLOCK Handle,
		       ACPI_CPU_FLAGS Flags)
{
    if (AcpiInterrupt) {
	IoReleaseInterruptMutex(AcpiInterrupt);
    }
}

static NTAPI BOOLEAN AcpiIsr(PKINTERRUPT Interrupt, PVOID ServiceContext)
{
    PACPI_ISR_CONTEXT Context = ServiceContext;
    return Context->Handler(Context->Context) == ACPI_INTERRUPT_HANDLED;
}

UINT32 AcpiOsInstallInterruptHandler(UINT32 InterruptNumber,
				     ACPI_OSD_HANDLER ServiceRoutine,
				     PVOID Context)
{
    if (AcpiInterrupt) {
	DPRINT1("Reregister interrupt attempt failed\n");
	return AE_ALREADY_EXISTS;
    }

    if (!ServiceRoutine) {
	DPRINT1("Bad parameter\n");
	return AE_BAD_PARAMETER;
    }

    DPRINT("AcpiOsInstallInterruptHandler()\n");

    AcpiIsrContext.Handler = ServiceRoutine;
    AcpiIsrContext.Context = Context;
    AcpiIsrContext.IrqNumber = InterruptNumber;

    /* We should really set ShareVector to TRUE but since interrupt sharing is not
     * yet implemented, we set it to FALSE for now. */
    NTSTATUS Status = IoConnectInterrupt(&AcpiInterrupt, AcpiIsr, &AcpiIsrContext,
					 InterruptNumber, InterruptNumber, InterruptNumber,
					 LevelSensitive, FALSE, 0, FALSE);

    if (!NT_SUCCESS(Status)) {
	DPRINT("Could not connect to interrupt %d\n", InterruptNumber);
	return AE_ERROR;
    }
    return AE_OK;
}

ACPI_STATUS AcpiOsRemoveInterruptHandler(UINT32 InterruptNumber,
					 ACPI_OSD_HANDLER ServiceRoutine)
{
    DPRINT("AcpiOsRemoveInterruptHandler()\n");

    if (!ServiceRoutine) {
	DPRINT1("Bad parameter\n");
	return AE_BAD_PARAMETER;
    }

    if (!AcpiInterrupt) {
	DPRINT1("Trying to remove non-existing interrupt handler\n");
	return AE_NOT_EXIST;
    }

    IoDisconnectInterrupt(AcpiInterrupt);
    AcpiInterrupt = NULL;
    memset(&AcpiIsrContext, 0, sizeof(ACPI_ISR_CONTEXT));
    return AE_OK;
}

static VOID OslReadMemory(PVOID MappedAddress,
			  UINT64 *Value,
			  UINT32 Width)
{
    switch (Width) {
    case 8:
	*Value = *(PUCHAR)MappedAddress;
	break;

    case 16:
	*Value = *(PUSHORT)MappedAddress;
	break;

    case 32:
	*Value = *(PULONG)MappedAddress;
	break;

    case 64:
	*Value = *(PULONGLONG)MappedAddress;
	break;

    default:
	DPRINT1("AcpiOsReadMemory got bad width: %d\n", Width);
	RtlRaiseStatus(STATUS_INVALID_PARAMETER);
    }
}

ACPI_STATUS AcpiOsReadMemory(ACPI_PHYSICAL_ADDRESS Address,
			     UINT64 *Value,
			     UINT32 Width)
{
    DPRINT("AcpiOsReadMemory 0x%llx\n", Address);
    PVOID MappedAddress = AcpiOsMapMemory(Address, Width);
    if (!MappedAddress) {
	return AE_ERROR;
    }
    OslReadMemory(MappedAddress, Value, Width);
    return AE_OK;
}

static VOID OslWriteMemory(PVOID MappedAddress,
			   UINT64 Value,
			   UINT32 Width)
{
    switch (Width) {
    case 8:
	*(PUCHAR)MappedAddress = Value;
	break;

    case 16:
	*(PUSHORT)MappedAddress = Value;
	break;

    case 32:
	*(PULONG)MappedAddress = Value;
	break;

    case 64:
	*(PULONGLONG)MappedAddress = Value;
	break;

    default:
	DPRINT1("AcpiOsWriteMemory got bad width: %d\n", Width);
	RtlRaiseStatus(STATUS_INVALID_PARAMETER);
    }
}

ACPI_STATUS AcpiOsWriteMemory(ACPI_PHYSICAL_ADDRESS Address,
			      UINT64 Value,
			      UINT32 Width)
{
    DPRINT("AcpiOsWriteMemory 0x%llx\n", Address);
    PVOID MappedAddress = AcpiOsMapMemory(Address, Width);
    if (!MappedAddress) {
	return AE_ERROR;
    }

    OslWriteMemory(MappedAddress, Value, Width);
    return AE_OK;
}

ACPI_STATUS AcpiOsReadPort(ACPI_IO_ADDRESS Address,
			   UINT32 *Value,
			   UINT32 Width)
{
    DPRINT("AcpiOsReadPort 0x%llx, width %d\n", Address, Width);

    switch (Width) {
    case 8:
	*Value = READ_PORT_UCHAR((PUCHAR)(ULONG_PTR)Address);
	break;

    case 16:
	*Value = READ_PORT_USHORT((PUSHORT)(ULONG_PTR)Address);
	break;

    case 32:
	*Value = READ_PORT_ULONG((PULONG)(ULONG_PTR)Address);
	break;

    default:
	DPRINT1("AcpiOsReadPort got bad width: %d\n", Width);
	return AE_BAD_PARAMETER;
	break;
    }
    return AE_OK;
}

ACPI_STATUS AcpiOsWritePort(ACPI_IO_ADDRESS Address,
			    UINT32 Value,
			    UINT32 Width)
{
    DPRINT("AcpiOsWritePort 0x%llx, width %d\n", Address, Width);
    switch (Width) {
    case 8:
	WRITE_PORT_UCHAR((PUCHAR)(ULONG_PTR)Address, Value);
	break;

    case 16:
	WRITE_PORT_USHORT((PUSHORT)(ULONG_PTR)Address, Value);
	break;

    case 32:
	WRITE_PORT_ULONG((PULONG)(ULONG_PTR)Address, Value);
	break;

    default:
	DPRINT1("AcpiOsWritePort got bad width: %d\n", Width);
	return AE_BAD_PARAMETER;
	break;
    }
    return AE_OK;
}

#define CFG_SHIFT	12

static PVOID OslGetPciConfigurationAddress(ACPI_PCI_ID *PciId,
					   UINT32 Reg)
{
    ULONG64 PhyAddr = 0;
    ACPI_TABLE_MCFG *Table;
    ACPI_STATUS Status = AcpiGetTable(ACPI_SIG_MCFG, 0, (ACPI_TABLE_HEADER **)&Table);
    if (ACPI_FAILURE(Status)) {
	DPRINT1("Failed to get MCFG table (Status 0x%08x)\n", Status);
	return NULL;
    }
    ACPI_MCFG_ALLOCATION *Entry = (PVOID)(Table + 1);
    ULONG EntryCount = (Table->Header.Length - sizeof(*Table)) / sizeof(*Entry);
    for (ULONG i = 0; i < EntryCount; i++) {
	if (Entry[i].PciSegment == PciId->Segment &&
	    Entry[i].StartBusNumber <= PciId->Bus &&
	    Entry[i].EndBusNumber >= PciId->Bus) {
	    PhyAddr = Entry[i].Address;
	    break;
	}
    }
    if (!PhyAddr) {
	DPRINT("No MCFG table entry found for PCI segment %d bus %d\n",
	       PciId->Segment, PciId->Bus);
	return NULL;
    }
    PhyAddr += ((PciId->Bus << 8) | (PciId->Device << 3) | PciId->Function) << CFG_SHIFT;
    PPCI_COMMON_CONFIG PciCfg = AcpiOsMapMemory(PhyAddr, 1 << CFG_SHIFT);
    if (!PciCfg) {
	DPRINT("Unable to map physical memory %llx\n", PhyAddr);
	return NULL;
    }
    if (PciCfg->Header.VendorID == PCI_INVALID_VENDORID) {
	DPRINT("Invalid vendor ID in PCI configuration space\n");
	return NULL;
    }

    DPRINT("PCI device is present\n");
    return (PCHAR)PciCfg + Reg;
}

ACPI_STATUS AcpiOsReadPciConfiguration(ACPI_PCI_ID *PciId,
				       UINT32 Reg, UINT64 *Value, UINT32 Width)
{
    DPRINT("AcpiOsReadPciConfiguration, segment=%d, bus=%d, device=%d, func=%d, reg=0x%x\n",
	   PciId->Device, PciId->Bus, PciId->Device, PciId->Function, Reg);

    PVOID MappedReg = OslGetPciConfigurationAddress(PciId, Reg);
    if (!MappedReg) {
	return AE_NOT_FOUND;
    }

    OslReadMemory(MappedReg, Value, Width);
    return AE_OK;
}

ACPI_STATUS AcpiOsWritePciConfiguration(ACPI_PCI_ID *PciId,
					UINT32 Reg, UINT64 Value, UINT32 Width)
{
    DPRINT("AcpiOsWritePciConfiguration, segment=%d, bus=%d, device=%d, func=%d, reg=0x%x\n",
	   PciId->Device, PciId->Bus, PciId->Device, PciId->Function, Reg);

    PVOID MappedReg = OslGetPciConfigurationAddress(PciId, Reg);
    if (!MappedReg) {
	return AE_NOT_FOUND;
    }

    OslWriteMemory(MappedReg, Value, Width);
    return AE_OK;
}

VOID ACPI_INTERNAL_VAR_XFACE AcpiOsPrintf(const char *Fmt, ...)
{
    va_list Args;
    va_start(Args, Fmt);

    AcpiOsVprintf(Fmt, Args);

    va_end(Args);
}

VOID AcpiOsVprintf(const char *Fmt, va_list Args)
{
#ifndef NDEBUG
    vDbgPrintEx(-1, DPFLTR_ERROR_LEVEL, Fmt, Args);
#endif
}

VOID AcpiOsRedirectOutput(PVOID Destination)
{
    /* No-op */
    DPRINT1("Output redirection not supported\n");
}

UINT64 AcpiOsGetTimer(VOID)
{
    LARGE_INTEGER CurrentTime;

    NtQuerySystemTime(&CurrentTime);
    return CurrentTime.QuadPart;
}

VOID AcpiOsWaitEventsComplete(VOID)
{
    /*
     * Wait for all asynchronous events to complete.
     * This implementation does nothing.
     */
}

ACPI_STATUS AcpiOsSignal(UINT32 Function, PVOID Info)
{
    ACPI_SIGNAL_FATAL_INFO *FatalInfo = Info;

    switch (Function) {
    case ACPI_SIGNAL_FATAL:
	if (Info)
	    DPRINT1("AcpiOsBreakpoint: %d %d %d ****\n", FatalInfo->Type, FatalInfo->Code,
		    FatalInfo->Argument);
	else
	    DPRINT1("AcpiOsBreakpoint ****\n");
	break;
    case ACPI_SIGNAL_BREAKPOINT:
	if (Info)
	    DPRINT1("AcpiOsBreakpoint: %p ****\n", Info);
	else
	    DPRINT1("AcpiOsBreakpoint ****\n");
	break;
    }

    ASSERT(FALSE);

    return AE_OK;
}

ACPI_STATUS AcpiOsEnterSleep(UINT8 SleepState, UINT32 RegaValue, UINT32 RegbValue)
{
    DPRINT1("Entering sleep state S%u.\n", SleepState);
    return AE_OK;
}

ACPI_STATUS AcpiOsGetLine(char *Buffer, UINT32 BufferLength, UINT32 *BytesRead)
{
    DPRINT1("File reading not supported\n");
    return AE_ERROR;
}
