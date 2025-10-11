#include "halp.h"

#if defined(_M_IX86) || defined(_M_AMD64)

/* Prevent the compiler from re-ordering any write which follows the fence
 * in program order with any read or write which preceeds the fence in
 * program order. */
#define COMPILER_MEMORY_RELEASE() __atomic_signal_fence(__ATOMIC_RELEASE)

/* Memory mapped registers for each HPET timer, starting at offset TIMERS_OFFSET */
typedef volatile struct _HPET_MMIO_REGISTERS {
    ULONG64 Config;
    ULONG64 Comparator;
    ULONG64 FsbInterruptRoute;
    CHAR Padding[8];
} HPET_MMIO_REGISTERS, *PHPET_MMIO_REGISTERS;

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

/* On an i386/amd64 system, the seL4 kernel uses the first 32 interrupt vectors
 * for internal purposes (eg. invalid instruction faults, page faults, etc).
 * The start of the device IRQ vectors is 0x20. */
#define IRQ0_CPU_VECTOR	0x20

static BOOLEAN HalpHpetUseMsi;	/* Set this to TRUE to enable MSI for HPET */
extern ULONG HalpNumHpetTables;
extern HAL_HPET HalpHpetTable[];

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

/*
 * Enable the system timer and configure it to fire with the given period.
 * The specified period is in unit of 100ns.
 *
 * This routine assumes that the page at EX_DYN_VSPACE_START is unmapped.
 * It can only be called once, during system startup.
 */
NTSTATUS HalpEnableHpet(OUT PIRQ_HANDLER IrqHandler,
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
		Irq = ULONG_MAX; /* Irq is unused for MSI */
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
	    /* HPET interrupts are always active-high and edge-triggered. */
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

#endif	/* defined(_M_IX86) || defined(_M_AMD64) */
