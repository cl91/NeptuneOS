#include "halp.h"

HAL_ACPI_RSDP HalpAcpiRsdp;

#if defined(_M_IX86) || defined(_M_AMD64)

#ifndef CONFIG_IRQ_IOAPIC
#error "You must enable IOAPIC for i386/amd64 systems"
#endif

#include <pshpack1.h>
/* ACPI System Descriptor Table Header */
typedef struct _ACPI_TABLE_HEADER {
    CHAR Signature[4];
    ULONG Length;
    UCHAR Revision;
    UCHAR Checksum;
    CHAR OemID[6];
    CHAR OemTableID[8];
    ULONG OemRevision;
    ULONG CreatorID;
    ULONG CreatorRevision;
} ACPI_TABLE_HEADER, *PACPI_TABLE_HEADER;

typedef struct _ACPI_SUBTABLE_HEADER {
    UCHAR Type;
    UCHAR Length;
} ACPI_SUBTABLE_HEADER, *PACPI_SUBTABLE_HEADER;

typedef struct _ACPI_MADT {
    ACPI_TABLE_HEADER Header;
    ULONG Address;		/* Physical address of local APIC */
    ULONG Flags;
    ACPI_SUBTABLE_HEADER Subtables[];
} ACPI_MADT, *PACPI_MADT;

typedef struct _ACPI_MADT_LOCAL_APIC {
    ACPI_SUBTABLE_HEADER Header;
    UCHAR ProcessorId;		/* ACPI Processor Id */
    UCHAR Id;			/* Local APIC Id */
    ULONG Flags;		/* Bit 0 = Processor Enabled. Bit 1 = Online Capable. */
} ACPI_MADT_LOCAL_APIC, *PACPI_MADT_LOCAL_APIC;

typedef struct _ACPI_MADT_IO_APIC {
    ACPI_SUBTABLE_HEADER Header;
    UCHAR Id;			/* IO APIC Id */
    UCHAR Reserved;		/* Reserved. Must be zero */
    ULONG Address;		/* APIC physical address */
    ULONG GlobalIrqBase;	/* Global system interrupt where INTI lines start */
} ACPI_MADT_IO_APIC, *PACPI_MADT_IO_APIC;

typedef struct _ACPI_MADT_INTERRUPT_SOURCE_OVERRIDE {
    ACPI_SUBTABLE_HEADER Header;
    UCHAR BusSource;
    UCHAR IrqSource;
    ULONG GlobalIrq;		/* Global system interrupt */
    USHORT Flags;
} ACPI_MADT_INTERRUPT_SOURCE_OVERRIDE, *PACPI_MADT_INTERRUPT_SOURCE_OVERRIDE;

typedef struct _ACPI_MADT_LOCAL_X2APIC {
    ACPI_SUBTABLE_HEADER Header;
    USHORT Reserved;
    ULONG Id;			/* Processor's local x2APIC Id */
    ULONG Flags;		/* Bit 0 = Processor Enabled. Bit 1 = Online Capable. */
    ULONG ProcessorId;		/* ACPI Processor Id */
} ACPI_MADT_LOCAL_X2APIC, *PACPI_MADT_LOCAL_X2APIC;

#define ACPI_MADT_TYPE_LOCAL_APIC 0
#define ACPI_MADT_TYPE_IO_APIC 1
#define ACPI_MADT_TYPE_INTERRUPT_SOURCE_OVERRIDE 2
#define ACPI_MADT_TYPE_LOCAL_X2APIC 9

typedef struct _ACPI_GENERIC_ADDRESS {
    UCHAR SpaceId;	    /* Address space (memory or IO port) */
    UCHAR BitWidth;	    /* Size in bits of given register */
    UCHAR BitOffset;	    /* Bit offset within the register */
    UCHAR AccessWidth;	    /* Minimum Access size (ACPI 3.0) */
    ULONG64 Address;	    /* Physical address of struct or register */
} ACPI_GENERIC_ADDRESS, *PACPI_GENERIC_ADDRESS;

#define ACPI_ADDRESS_ID_SYSTEM_MEMORY	0

typedef struct _ACPI_HPET_TABLE {
    ACPI_TABLE_HEADER Header;
    UCHAR HardwareRevId;
    UCHAR MaxComparatorId : 5;
    UCHAR CounterSize : 1;
    UCHAR Reserved : 1;
    UCHAR LegacyReplacement : 1;
    USHORT PciVendorId;
    ACPI_GENERIC_ADDRESS BaseAddress;
    UCHAR HpetIndex;
    USHORT MinTicks;
    UCHAR PageProtection;
} ACPI_HPET_TABLE, *PACPI_HPET_TABLE;

#define MAX_NUM_HPET_TABLES	16

/* The 16 interrupt vectors following IRQ0_CPU_VECTOR are reserved for PIC
 * interrupts, and we do not use them on IO APIC systems. */
#define NUM_PIC_IRQS	16

#define MAX_NUM_INTERRUPT_SOURCE_OVERRIDE	NUM_PIC_IRQS

typedef struct _HAL_LOCAL_APIC {
    ULONG ApicId;
    ULONG AcpiId;
} HAL_LOCAL_APIC, *PHAL_LOCAL_APIC;

static ULONG HalpNumIoApic;
HAL_IO_APIC HalpIoApicTable[CONFIG_MAX_NUM_IOAPIC];
static ULONG HalpNumProcessors;
static HAL_LOCAL_APIC HalpLocalApicTable[CONFIG_MAX_NUM_NODES];
ULONG HalpNumHpetTables;
HAL_HPET HalpHpetTable[MAX_NUM_HPET_TABLES];
ULONG HalpNumInterruptSourceOverride;
HAL_INTERRUPT_SOURCE_OVERRIDE HalpInterruptSourceOverrideTable[MAX_NUM_INTERRUPT_SOURCE_OVERRIDE];

VOID HalAcpiRegisterRsdp(IN PHAL_ACPI_RSDP Rsdp)
{
    HalpAcpiRsdp = *Rsdp;
}

static BOOLEAN HalpAcpiTableChecksumValid(IN PACPI_TABLE_HEADER Table)
{
    UCHAR Sum = 0;
    for (ULONG i = 0; i < Table->Length; i++) {
        Sum += ((PCHAR)Table)[i];
    }
    return !Sum;
}

static NTSTATUS HalpAcpiMapTable(IN ULONG64 PhyAddr,
				 OUT PACPI_TABLE_HEADER *Table,
				 IN PCHAR *Signatures,
				 IN ULONG SignatureCount)
{
    assert(Signatures);
    ULONG64 AlignedAddr = PAGE_ALIGN64(PhyAddr);
    *Table = (PVOID)(MWORD)(PhyAddr - AlignedAddr + EX_DYN_VSPACE_START);
    ULONG WindowSize = PAGE_ALIGN_UP64(PhyAddr + sizeof(ACPI_TABLE_HEADER)) - AlignedAddr;
    RET_ERR(MmMapPhysicalMemory(AlignedAddr, EX_DYN_VSPACE_START,
				WindowSize, PAGE_READONLY));
    /* Do not map the table if signature does not match any of the given signatures. */
    BOOLEAN Match = FALSE;
    for (ULONG i = 0; i < SignatureCount; i++) {
	if (!strncmp((*Table)->Signature, Signatures[i], 4)) {
	    Match = TRUE;
	    break;
	}
    }
    if (!Match) {
	MmUnmapPhysicalMemory((MWORD)(*Table));
	return STATUS_INVALID_SIGNATURE;
    }
    /* Reject the table if checksum fails */
    if (!HalpAcpiTableChecksumValid(*Table)) {
	assert(FALSE);
	MmUnmapPhysicalMemory((MWORD)(*Table));
	return STATUS_DATA_CHECKSUM_ERROR;
    }
    if (PhyAddr + (*Table)->Length > PAGE_ALIGN_UP64(PhyAddr + sizeof(ACPI_TABLE_HEADER))) {
	MmUnmapPhysicalMemory((MWORD)(*Table));
	WindowSize = PAGE_ALIGN_UP64(PhyAddr + (*Table)->Length) - AlignedAddr;
	RET_ERR(MmMapPhysicalMemory(AlignedAddr, EX_DYN_VSPACE_START,
				    WindowSize, PAGE_READONLY));
    }
    return STATUS_SUCCESS;
}

static VOID HalpAcpiRegisterMadt(IN PACPI_MADT Madt)
{
    ULONG LengthProcessed = sizeof(ACPI_MADT);
    while (LengthProcessed < Madt->Header.Length) {
	PACPI_SUBTABLE_HEADER Subtable = (PVOID)((PCHAR)Madt + LengthProcessed);
	LengthProcessed += Subtable->Length;
	switch (Subtable->Type) {
	case ACPI_MADT_TYPE_LOCAL_APIC:
	{
	    PACPI_MADT_LOCAL_APIC LocalApic = (PACPI_MADT_LOCAL_APIC)Subtable;
	    if (LocalApic->Flags == 1) {
		HalpLocalApicTable[HalpNumProcessors].ApicId = LocalApic->Id;
		HalpLocalApicTable[HalpNumProcessors].AcpiId = LocalApic->ProcessorId;
		HalpNumProcessors++;
	    }
	    break;
	}
	case ACPI_MADT_TYPE_IO_APIC:
	    if (HalpNumIoApic < CONFIG_MAX_NUM_IOAPIC) {
		HalpIoApicTable[HalpNumIoApic].GlobalIrqBase =
		    ((PACPI_MADT_IO_APIC)Subtable)->GlobalIrqBase;
		HalpNumIoApic++;
	    }
	    break;
	case ACPI_MADT_TYPE_INTERRUPT_SOURCE_OVERRIDE:
	    if (HalpNumInterruptSourceOverride < MAX_NUM_INTERRUPT_SOURCE_OVERRIDE) {
		PACPI_MADT_INTERRUPT_SOURCE_OVERRIDE Table = (PVOID)Subtable;
		HalpInterruptSourceOverrideTable[HalpNumInterruptSourceOverride].IrqSource =
		    Table->IrqSource;
		HalpInterruptSourceOverrideTable[HalpNumInterruptSourceOverride].GlobalIrq =
		    Table->GlobalIrq;
		/*
		 * Advanced Configuration and Power Interface Specification, Release 6.5
		 * Section 5.2.12.5 Interrupt Source Override Structure
		 * Table 5.26: MPS INTI Flags
		 * ----------------------------------------------------------------
		 * Local APIC	Bit	Bit	Description
		 * Flags	Length	Offset
		 * ----------------------------------------------------------------
		 * Polarity	2	0	Polarity of the APIC I/O input signals:
		 *				00 Conforms to the specifications of the
		 *				   bus (for example, EISA is active-low
		 *				   for level-triggered interrupts).
		 *				01 Active high
		 *				10 Reserved
		 *				11 Active low
		 * Trigger	2	2	Trigger mode of the APIC I/O input signals:
		 * Mode				00 Conforms to specifications of the bus
		 *				   (For example, ISA is edge-triggered).
		 *				01 Edge-triggered
		 *				10 Reserved
		 *				11 Level-triggered
		 */
		HalpInterruptSourceOverrideTable[HalpNumInterruptSourceOverride].LevelSensitive =
		    Table->Flags & 8;
		HalpInterruptSourceOverrideTable[HalpNumInterruptSourceOverride].ActiveLow =
		    Table->Flags & 2;
		HalpNumInterruptSourceOverride++;
	    }
	    break;
	case ACPI_MADT_TYPE_LOCAL_X2APIC:
	{
	    PACPI_MADT_LOCAL_X2APIC LocalApic = (PACPI_MADT_LOCAL_X2APIC)Subtable;
	    if (LocalApic->Flags == 1) {
		HalpLocalApicTable[HalpNumProcessors].ApicId = LocalApic->Id;
		HalpLocalApicTable[HalpNumProcessors].AcpiId = LocalApic->ProcessorId;
		HalpNumProcessors++;
	    }
	    break;
	}
	default:
	    continue;
	}
    }
}

static VOID HalpAcpiRegisterHpet(IN PACPI_HPET_TABLE Hpet)
{
    if (Hpet->BaseAddress.SpaceId != ACPI_ADDRESS_ID_SYSTEM_MEMORY) {
	/* HPET should always be accessed using MMIO. */
	assert(FALSE);
	return;
    }
    if (HalpNumHpetTables >= MAX_NUM_HPET_TABLES) {
	assert(FALSE);
	return;
    }
    HalpHpetTable[HalpNumHpetTables].BaseAddress = Hpet->BaseAddress.Address;
    HalpNumHpetTables++;
}

static VOID HalpAcpiRegisterTable(IN ULONG64 PhyAddr)
{
    PCHAR MatchSignatures[] = { "APIC", "HPET" };
    PACPI_TABLE_HEADER Table = NULL;
    if (NT_SUCCESS(HalpAcpiMapTable(PhyAddr, &Table, MatchSignatures,
				    ARRAYSIZE(MatchSignatures)))) {
	if (!strncmp(Table->Signature, "APIC", 4)) {
	    HalpAcpiRegisterMadt((PACPI_MADT)Table);
	} else if (!strncmp(Table->Signature, "HPET", 4)) {
	    HalpAcpiRegisterHpet((PACPI_HPET_TABLE)Table);
	} else {
	    assert(FALSE);
	}
	MmUnmapPhysicalMemory((MWORD)Table);
    }
}

NTSTATUS HalpInitAcpi(VOID)
{
    ULONG64 XsdtAddress = HalpAcpiRsdp.XsdtAddress ?
	HalpAcpiRsdp.XsdtAddress : HalpAcpiRsdp.RsdtAddress;
    ULONG PtrSize = HalpAcpiRsdp.XsdtAddress && HalpAcpiRsdp.Revision ? 8 : 4;
    assert(XsdtAddress);
    PACPI_TABLE_HEADER Xsdt = NULL;
    PCHAR XsdtSignatures[] = { "RSDT", "XSDT" };
    RET_ERR(HalpAcpiMapTable(XsdtAddress, &Xsdt, XsdtSignatures, ARRAYSIZE(XsdtSignatures)));
    ULONG PtrCount = (Xsdt->Length - sizeof(ACPI_TABLE_HEADER)) / PtrSize;
    HalpAllocateArray(Tables, ULONG64, PtrCount);
    if (PtrSize == 4) {
	PULONG TablePtrs = (PVOID)(Xsdt + 1);
	for (ULONG i = 0; i < PtrCount; i++) {
	    Tables[i] = TablePtrs[i];
	}
    } else {
	PULONG64 TablePtrs = (PVOID)(Xsdt + 1);
	for (ULONG i = 0; i < PtrCount; i++) {
	    Tables[i] = TablePtrs[i];
	}
    }
    MmUnmapPhysicalMemory((MWORD)Xsdt);
    for (ULONG i = 0; i < PtrCount; i++) {
	HalpAcpiRegisterTable(Tables[i]);
    }
    HalpFreePool(Tables);
    return STATUS_SUCCESS;
}

/* Search the IO APIC table to determine which IO APIC to connect to
 * and the pin number, using the raw (untranslated) interrupt vector.
 * This is assuming the global system interrupt windows of each IO APIC
 * is consecutive and ordered in an ascending fashion. */
static NTSTATUS HalpGetIoApicPin(IN ULONG Irq,
				 OUT ULONG *pIoApic,
				 OUT ULONG *Pin)
{
    LONG IoApic = -1;
    while ((IoApic + 1) < HalpNumIoApic) {
	if (Irq >= HalpIoApicTable[IoApic + 1].GlobalIrqBase) {
	    IoApic++;
	    continue;
	} else {
	    break;
	}
    }
    if (IoApic < 0) {
	return STATUS_NO_SUCH_DEVICE;
    }
    *pIoApic = IoApic;
    *Pin = Irq - HalpIoApicTable[IoApic].GlobalIrqBase;
    return STATUS_SUCCESS;
}

NTSTATUS HalAllocateIrq(IN ULONG Irq)
{
    ULONG IoApic, Pin;
    RET_ERR(HalpGetIoApicPin(Irq, &IoApic, &Pin));
    if (HalpIsApicPinAssigned(IoApic, Pin)) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    HalpSetApicPinAssigned(IoApic, Pin);
    return STATUS_SUCCESS;
}

NTSTATUS HalDeallocateIrq(IN ULONG Irq)
{
    ULONG IoApic, Pin;
    RET_ERR(HalpGetIoApicPin(Irq, &IoApic, &Pin));
    if (!HalpIsApicPinAssigned(IoApic, Pin)) {
	return STATUS_NO_SUCH_DEVICE;
    }
    HalpSetApicPinFree(IoApic, Pin);
    return STATUS_SUCCESS;
}

#define SEL4_ERROR_TO_NTSTATUS(x)			\
    ({							\
	int Error = (x);				\
	if (Error) {					\
	    KeDbgDumpIPCError(Error);			\
	}						\
	Error ? SEL4_ERROR(Error) : STATUS_SUCCESS;	\
    })

/*
 * Note: before calling this routine, you must have initialized the
 * IRQ_HANDLER object with the assigned IRQ line, CPU vector, and
 * relevant flags.
 */
NTSTATUS HalGetIrqCap(IN PIRQ_HANDLER IrqHandler,
		      IN MWORD Root, IN MWORD Index, IN UINT8 Depth)
{
    /* On an i386/amd64 system, the first 16 interrupts are reserved for PIC
     * interrupts. Note if the seL4 kernel is configured to use the IO APIC,
     * the following call will always fail. */
    if (IrqHandler->Vector < NUM_PIC_IRQS) {
	return SEL4_ERROR_TO_NTSTATUS(seL4_IRQControl_Get(seL4_CapIRQControl,
							  IrqHandler->Vector,
							  Root, Index, Depth));
    }
    /* The translated vector corresponds to the CPU interrupt vector to which
     * this IRQ should be delivered. This parameter is zero-based (ie.
     * IrqHandler->Vector == 0 corresponds to the start of the CPU interrupt
     * vectors assignable to devices, which on i386/amd64 is 0x20). Note on IO
     * APIC system the first 16 interrupts are always masked as these are PIC
     * IRQ lines. Therefore, the smallest IrqHandler->Vector obtained from the
     * IO resources allocator on an IO APIC system is 0x10. When passing this
     * parameter to seL4_IRQControl_GetMSI or seL4_IRQControl_GetIOAPIC, one
     * should further subtract 0x10 from IrqHandler->Vector (because this is
     * what the seL4 kernel expects --- it will add the offset 0x20 + 0x10 to
     * obtain the actual CPU interrupt vector). */
    ULONG Vector = IrqHandler->Vector - NUM_PIC_IRQS;
    /* If the caller requested messaged interrupt, request an MSI cap. */
    if (IrqHandler->Config.Msi) {
	return SEL4_ERROR_TO_NTSTATUS(seL4_IRQControl_GetMSI(seL4_CapIRQControl,
							     Root, Index, Depth,
							     IrqHandler->Config.Bus,
							     IrqHandler->Config.Device,
							     IrqHandler->Config.Function,
							     IrqHandler->Message,
							     Vector));
    }
    ULONG IoApic = ULONG_MAX;
    ULONG Pin = ULONG_MAX;
    RET_ERR(HalpGetIoApicPin(IrqHandler->Irq, &IoApic, &Pin));
    assert(IoApic != ULONG_MAX);
    assert(Pin != ULONG_MAX);
    return SEL4_ERROR_TO_NTSTATUS(seL4_IRQControl_GetIOAPIC(seL4_CapIRQControl,
							    Root, Index, Depth,
							    IoApic, Pin,
							    IrqHandler->Config.Level,
							    IrqHandler->Config.Polarity,
							    Vector));
}

NTSTATUS HalMaskUnusableInterrupts(VOID)
{
    /* Mask the first 16 interrupts which are reserved for PIC IRQs. */
    for (ULONG i = 0; i < NUM_PIC_IRQS; i++) {
	IoMaskInterruptVector(i);
    }
    return STATUS_SUCCESS;
}

ULONG_PTR HalComputeInterruptMessageAddress(IN ULONG ProcessorId)
{
    assert(HalpNumProcessors);
    if (ProcessorId >= HalpNumProcessors) {
	assert(FALSE);
	ProcessorId = 0;
    }
    return 0xFEE00000ULL | (HalpLocalApicTable[ProcessorId].ApicId << 12);
}

ULONG HalComputeInterruptMessageData(IN ULONG Vector)
{
    return Vector + IRQ0_CPU_VECTOR;
}

/* Inform the caller of whether we got an RSDT or an XSDT. If we are running
 * on a BIOS with ACPI 1.0 (or if the XSDT address is NULL, which for ACPI >= 2.0
 * is a violation of the ACPI specs), we have an RSDT. Otherwise it's an XSDT. */
ULONG64 HalAcpiGetRsdt(OUT ULONG *Length)
{
    assert(HalpAcpiRsdp.XsdtAddress || HalpAcpiRsdp.RsdtAddress);
    *Length = HalpAcpiRsdp.XsdtAddress && HalpAcpiRsdp.Revision ? 8 : 4;
    return HalpAcpiRsdp.XsdtAddress ? HalpAcpiRsdp.XsdtAddress : HalpAcpiRsdp.RsdtAddress;
}

VOID HalAcpiDumpRsdp(IN PHAL_ACPI_RSDP Rsdp, IN ULONG Indentation)
{
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("RSDP %p\n", Rsdp);
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("Signature %c%c%c%c%c%c%c%c\n", Rsdp->Signature[0],
	     Rsdp->Signature[1], Rsdp->Signature[2], Rsdp->Signature[3],
	     Rsdp->Signature[4], Rsdp->Signature[5], Rsdp->Signature[6],
	     Rsdp->Signature[7]);
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("Checksum 0x%x\n", Rsdp->Checksum);
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("OEMId %c%c%c%c%c%c\n", Rsdp->OemId[0],
	     Rsdp->OemId[1], Rsdp->OemId[2], Rsdp->OemId[3],
	     Rsdp->OemId[4], Rsdp->OemId[5]);
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("Revision %d\n", Rsdp->Revision);
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("RSDT Physical Address 0x%x\n", Rsdp->RsdtAddress);
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("RSDT Length 0x%x\n", Rsdp->Length);
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("XSDT Physical Address 0x%llx\n", Rsdp->XsdtAddress);
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("Extended Checksum 0x%x\n", Rsdp->ExtendedChecksum);
}

#endif	/* defined(_M_IX86) || defined(_M_AMD64) */
