#include "halp.h"

HAL_ACPI_RSDP HalpAcpiRsdp;

#if (defined(_M_IX86) || defined(_M_AMD64)) && !CONFIG_IRQ_IOAPIC
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

typedef struct _ACPI_MADT_IO_APIC {
    ACPI_SUBTABLE_HEADER Header;
    UCHAR Id;			/* IO APIC Id */
    UCHAR Reserved;		/* Reserved. Must be zero */
    ULONG Address;		/* APIC physical address */
    ULONG GlobalIrqBase;	/* Global system interrupt where INTI lines start */
} ACPI_MADT_IO_APIC, *PACPI_MADT_IO_APIC;

#define ACPI_MADT_TYPE_IO_APIC 1

typedef struct _ACPI_GENERIC_ADDRESS {
    UCHAR SpaceId;	    /* Address space (memory or IO port) */
    UCHAR BitWidth;	    /* Size in bits of given register */
    UCHAR BitOffset;	    /* Bit offset within the register */
    UCHAR AccessWidth;	    /* Minimum Access size (ACPI 3.0) */
    ULONG64 Address;	    /* Physical address of struct or register */
} ACPI_GENERIC_ADDRESS, *PACPI_GENERIC_ADDRESS;

#define ACPI_ADDRESS_ID_SYSTEM_MEMORY	0

typedef struct _ACPI_HPET {
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
} ACPI_HPET, *PACPI_HPET;

/* Memory mapped registers for each HPET timer, starting at offset TIMERS_OFFSET */
typedef volatile struct _HPET_MMIO_REGISTERS {
    ULONG64 Config;
    ULONG64 Comparator;
    ULONG64 FsbInterruptRoute;
    CHAR Padding[8];
} HPET_MMIO_REGISTERS, *PHPET_MMIO_REGISTERS;
#include <poppack.h>

/* Offsets from the base address of the HPET MMIO region */
#define CAP_ID_REG 0x0
#define GENERAL_CONFIG_REG 0x10
#define MAIN_COUNTER_REG 0xF0
#define TIMERS_OFFSET 0x100

/* HPET timer config bits */
enum {
    /* 0 is reserved */
    /* 0 if edge triggered, 1 if level triggered. */
    TN_INT_TYPE_CNF = 1,
    /* Set to 1 to cause an interrupt when main timer hits comparator for
     * this timer */
    TN_INT_ENB_CNF = 2,
    /* If this bit is 1 you can write a 1 to it for periodic interrupts,
     * or a 0 for non-periodic interrupts */
    TN_TYPE_CNF = 3,
    /* If this bit is 1, hardware supports periodic mode for this timer */
    TN_PER_INT_CAP = 4,
    /* 1 = timer is 64 bit, 0 = timer is 32 bit */
    TN_SIZE_CAP = 5,
    /* Writing 1 to this bit allows software to directly set a periodic timers
     * accumulator */
    TN_VAL_SET_CNF = 6,
    /* 7 is reserved */
    /* Set this bit to force the timer to be a 32-bit timer (only works on
     * a 64-bit timer) */
    TN_32MODE_CNF = 8,
    /* 5 bit wide field (9:13). Specifies routing for IO APIC if using */
    TN_INT_ROUTE_CNF = 9,
    /* Set this bit to force interrupt delivery to the front side bus,
     * don't use the IO APIC */
    TN_FSB_EN_CNF = 14,
    /* If this bit is one, bit TN_FSB_EN_CNF can be set */
    TN_FSB_INT_DEL_CAP = 15,
    /* Bits 16:31 are reserved */
    /* Read-only 32-bit field that specifies which routes in the IO APIC
     * this timer can be configured to take */
    TN_INT_ROUTE_CAP = 32
};

/* General HPET config bits */
enum {
    /* 1 if main counter is running and interrupts are enabled */
    ENABLE_CNF = 0,
    /* 1 if LegacyReplacementRoute is being used */
    LEG_RT_CNF = 1
};

/* MSI registers - used to configure front side bus delivery of the
 * HPET interrupt.
 *
 * For details see section 10.10 "APIC message passing mechanism
 * and protocol (P6 family,pentium processors)" in "Intel 64 and IA-32
 * Architectures Software Developers Manual, Volume 3 (3A, 3B & 3C),
 * System Programming Guide" */
/* Message value register layout */
enum {
    /* 0:7 irq_vector */
    IRQ_VECTOR = 0,
    /* 8:10 */
    DELIVERY_MODE = 8,
    /* 11:13 reserved */
    LEVEL_TRIGGER = 14,
    TRIGGER_MODE = 15,
    /* 16:32 reserved */
};

/* Message address register layout */
enum {
    /* 0:1 reserved */
    DESTINATION_MODE = 2,
    REDIRECTION_HINT = 3,
    /* 4:11 reserved */
    /* 12:19 Destination ID */
    DESTINATION_ID = 12,
    /* 20:31 Fixed value 0x0FEE */
    FIXED = 20
};

#define MAX_NUM_IOAPIC_PINS	256

typedef struct _HAL_IO_APIC {
    ULONG GlobalIrqBase;
    MWORD AssignedPins[MAX_NUM_IOAPIC_PINS / MWORD_BITS];
} HAL_IO_APIC, *PHAL_IO_APIC;

typedef struct _HAL_HPET {
    ULONG64 BaseAddress;  /* Base physical address of the MMIO region */
    BOOLEAN SystemTimer;  /* TRUE if this HPET is assigned as the system timer */
    UCHAR NumComparators; /* Total number of comparators of this timer */
    UCHAR ComparatorId;   /* Comparator ID in this HPET that is assigned as the system timer */
    ULONG TimerTick;	  /* Timer tick in units of femtoseconds (1e-15s) */
    ULONG64 Period;	  /* Period in units of femtoseconds (1e-15s) */
} HAL_HPET, *PHAL_HPET;

#define MAX_NUM_HPET_TABLES	16

/* Prevent the compiler from re-ordering any write which follows the fence
 * in program order with any read or write which preceeds the fence in
 * program order. */
#define COMPILER_MEMORY_RELEASE() __atomic_signal_fence(__ATOMIC_RELEASE)

/* On an i386/amd64 system, the seL4 kernel uses the first 32 interrupt vectors
 * for internal purposes (eg. invalid instruction faults, page faults, etc).
 * The start of the device IRQ vectors is 0x20. */
#define IRQ0_CPU_VECTOR	0x20
/* The 16 interrupt vectors following IRQ0_CPU_VECTOR are reserved for PIC
 * interrupts, and we do not use them on IO APIC systems. */
#define NUM_PIC_IRQS	16

static ULONG HalpNumIoApic;
static HAL_IO_APIC HalpIoApicTable[CONFIG_MAX_NUM_IOAPIC];
static ULONG HalpNumHpetTables;
static HAL_HPET HalpHpetTable[MAX_NUM_HPET_TABLES];
static BOOLEAN HalpHpetUseMsi;	/* Set this to TRUE to enable MSI for HPET */

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
	if (Subtable->Type != ACPI_MADT_TYPE_IO_APIC) {
	    continue;
	}
	HalpIoApicTable[HalpNumIoApic].GlobalIrqBase =
	    ((PACPI_MADT_IO_APIC)Subtable)->GlobalIrqBase;
	HalpNumIoApic++;
	if (HalpNumIoApic >= CONFIG_MAX_NUM_IOAPIC) {
	    break;
	}
    }
}

FORCEINLINE BOOLEAN HalpIsApicPinAssigned(IN ULONG ApicIndex,
					  IN ULONG Pin)
{
    assert(Pin < MAX_NUM_IOAPIC_PINS);
    if (Pin >= MAX_NUM_IOAPIC_PINS) {
	return FALSE;
    }
    return GetBit(HalpIoApicTable[ApicIndex].AssignedPins, Pin);
}

FORCEINLINE VOID HalpSetApicPinAssigned(IN ULONG ApicIndex,
					IN ULONG Pin)
{
    assert(Pin < MAX_NUM_IOAPIC_PINS);
    assert(!HalpIsApicPinAssigned(ApicIndex, Pin));
    if (Pin < MAX_NUM_IOAPIC_PINS) {
	SetBit(HalpIoApicTable[ApicIndex].AssignedPins, Pin);
    }
}

FORCEINLINE VOID HalpSetApicPinFree(IN ULONG ApicIndex,
				    IN ULONG Pin)
{
    assert(Pin < MAX_NUM_IOAPIC_PINS);
    assert(HalpIsApicPinAssigned(ApicIndex, Pin));
    if (Pin < MAX_NUM_IOAPIC_PINS) {
	ClearBit(HalpIoApicTable[ApicIndex].AssignedPins, Pin);
    }
}

FORCEINLINE volatile ULONG64 *HalpHpetGetGeneralConfig(MWORD VirtBase)
{
    return (volatile ULONG64 *)(VirtBase + GENERAL_CONFIG_REG);
}

FORCEINLINE volatile ULONG64 *HalpHpetGetMainCounter(MWORD VirtBase)
{
    return (volatile ULONG64 *)(VirtBase + MAIN_COUNTER_REG);
}

FORCEINLINE volatile ULONG64 *HalpHpetGetCapId(MWORD VirtBase)
{
    return (volatile ULONG64 *)(VirtBase + CAP_ID_REG);
}

FORCEINLINE PHPET_MMIO_REGISTERS HalpHpetGetTimerRegisters(MWORD VirtBase,
							   ULONG Index)
{
    return (PHPET_MMIO_REGISTERS)(VirtBase + TIMERS_OFFSET) + Index;
}

static VOID HalpAcpiRegisterHpet(IN PACPI_HPET Hpet)
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
    HalpHpetTable[HalpNumHpetTables].NumComparators = Hpet->MaxComparatorId + 1;
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
	    HalpAcpiRegisterHpet((PACPI_HPET)Table);
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

/*
 * Enable the system timer and configure it to fire with the given period.
 * The specified period is in unit of 100ns.
 *
 * This routine assumes that the page at EX_DYN_VSPACE_START is unmapped.
 * It can only be called once, during system startup.
 */
NTSTATUS HalEnableSystemTimer(OUT PIRQ_HANDLER IrqHandler,
			      IN ULONG64 Period)
{
    for (ULONG i = 0; i < HalpNumHpetTables; i++) {
	assert(!HalpHpetTable[i].SystemTimer);
	MWORD VirtBase = EX_DYN_VSPACE_START;
	NTSTATUS Status = MmMapPhysicalMemory(HalpHpetTable[i].BaseAddress,
					      VirtBase, PAGE_SIZE, PAGE_READWRITE);
	if (!NT_SUCCESS(Status)) {
	    assert(FALSE);
	    return Status;
	}

	/* Get the total number of timers that we can use. */
	UCHAR NumComparators = ((*HalpHpetGetCapId(VirtBase) >> 8) & 0x1F) + 1;
	assert(NumComparators == HalpHpetTable[i].NumComparators);

	for (UCHAR j = 0; j < NumComparators; j++) {
	    PHPET_MMIO_REGISTERS Timer = HalpHpetGetTimerRegisters(VirtBase, j);
	    ULONG64 ConfigBits = Timer->Config;
	    /* Skip the timer if it cannot be in periodic mode */
	    if (!(ConfigBits & (1ULL << TN_PER_INT_CAP))) {
		DbgTrace("Skipping HPET %d because it cannot be in periodic mode.\n", j);
		continue;
	    }
	    /* Skip this timer if it is 32 bit */
	    if (!(ConfigBits & (1ULL << TN_SIZE_CAP))) {
		DbgTrace("Skipping HPET %d because it is 32-bit.\n", j);
		continue;
	    }
	    ULONG Irq = 0;
	    if (HalpHpetUseMsi) {
		/* Skip this timer if MSI is request but this timer does not support it */
		if (!(ConfigBits & (1ULL << TN_FSB_INT_DEL_CAP))) {
		    DbgTrace("Skipping HPET %d because it does not support MSI.\n", j);
		    continue;
		}
		Irq = ULONG_PTR_MAX; /* Irq is unused for MSI */
	    } else {
		/* Get the allowed IO APIC pins for this HPET, subject to the constraint
		 * given by the IRQ mask in TN_INT_ROUTE_CAP. HPETs are always assumed to
		 * be wired to the zeroth IO APIC. If this is not the case, consider using
		 * MSI instead. */
		ULONG IrqMask = ConfigBits >> TN_INT_ROUTE_CAP;
		while (Irq < 32) {
		    if ((IrqMask & (1ULL << Irq)) && !HalpIsApicPinAssigned(0, Irq)) {
			HalpSetApicPinAssigned(0, Irq);
			break;
		    }
		    Irq++;
		}
		if (Irq >= 32) {
		    assert(FALSE);
		    DbgTrace("Failed to allocate an APIC pin for HPET (irq mask 0x%x)\n",
			     IrqMask);
		    continue;
		}
	    }
	    /* Allocate a CPU interrupt vector to deliver the timer interrupt to. */
	    ULONG Vector = ULONG_MAX;
	    Status = IoAllocateInterruptVector(&Vector);
	    if (!NT_SUCCESS(Status)) {
		assert(FALSE);
		DbgTrace("Failed to allocate an IRQ vector for HPET MSI\n");
		/* Since we are called during system startup, something is seriously
		 * wrong, so we exit the routine. */
		MmUnmapPhysicalMemory(VirtBase);
		return Status;
	    }
	    assert(Vector != ULONG_MAX);
	    IrqHandler->Vector = Vector;
	    IrqHandler->Config.Word = 0;
	    IrqHandler->Message = 0;
	    if (HalpHpetUseMsi) {
		IrqHandler->Irq = Irq;
		IrqHandler->Config.Msi = TRUE;
		/* Set the timer to deliver interrupts via the front side bus (using MSIs) */
		Timer->Config |= 1ULL << TN_FSB_EN_CNF;
		/* Set up the message address register and message value register so we
		 * receive MSIs for this timer. The top 32 bits are the message address
		 * register and the bottom 32 bits are the message value register. Note
		 * the message value register should be set to the CPU interrupt vector
		 * to which the timer interrupt is to be delivered, so we need to add
		 * the IRQ0 vector offset. */
		Timer->FsbInterruptRoute = ((0x0FEEULL << FIXED) << 32)
		    | (IrqHandler->Vector + IRQ0_CPU_VECTOR);
	    } else {
		/* Add the GSI base for the zeroth IO APIC to obtain the GSI. */
		IrqHandler->Irq = Irq + HalpIoApicTable[0].GlobalIrqBase;
		/* Remove any legacy replacement route so our interrupts go where we want
		 * them. NOTE: PIT will cease to function from here on. */
		*HalpHpetGetGeneralConfig(VirtBase) &= ~(1ULL << LEG_RT_CNF);
		/* Make sure we're not delivering by MSI. */
		Timer->Config &= ~(1ULL << TN_FSB_EN_CNF);
		/* Put the IO/APIC pin number. */
		Timer->Config &= ~(((1ULL << 5) - 1) << TN_INT_ROUTE_CNF);
		Timer->Config |= Irq << TN_INT_ROUTE_CNF;
	    }
	    /* Set the timer to periodic mode and edge-triggered. */
	    Timer->Config |= (1ULL << TN_TYPE_CNF) | (1ULL << TN_VAL_SET_CNF) |
		(1ULL << TN_INT_ENB_CNF);
	    Timer->Config &= ~(1ULL << TN_INT_TYPE_CNF);
	    COMPILER_MEMORY_RELEASE();
	    /* Convert the period (in 100ns) to units of femtoseconds (1e-15s) */
	    Period *= 100000000ULL;
	    HalpHpetTable[i].Period = Period;
	    /* Read the timer tick in units of femtoseconds (1e-15s) */
	    HalpHpetTable[i].TimerTick = *HalpHpetGetCapId(VirtBase) >> 32;
	    /* Conver the period to units of timer ticks */
	    Period /= HalpHpetTable[i].TimerTick;
	    /* Enable the main counter */
	    *HalpHpetGetGeneralConfig(VirtBase) |= 1ULL << ENABLE_CNF;
	    /* Set the comparator register of the timer */
	    Timer->Comparator = *HalpHpetGetMainCounter(VirtBase) + Period;
	    /* This second write to the comparator sets the accumulator of the timer.
	     * This behavior is the result of setting the TN_VAL_SET_CNF bit above. */
	    Timer->Comparator = Period;
	    MmUnmapPhysicalMemory(VirtBase);
	    HalpHpetTable[i].SystemTimer = TRUE;
	    HalpHpetTable[i].ComparatorId = j;
	    return STATUS_SUCCESS;
	}
	MmUnmapPhysicalMemory(VirtBase);
    }
    return STATUS_DEVICE_DOES_NOT_EXIST;
}

NTSTATUS HalMaskUnusableInterrupts(VOID)
{
    /* Mask the first 16 interrupts which are reserved for PIC IRQs. */
    for (ULONG i = 0; i < NUM_PIC_IRQS; i++) {
	IoMaskInterruptVector(i);
    }
    return STATUS_SUCCESS;
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
