#pragma once

#include <ntos.h>
#include <dmilib.h>

#if defined(_M_IX86) || defined(_M_AMD64)

/* Conversion functions */
#define BCD_INT(bcd)				\
    (((bcd & 0xF0) >> 4) * 10 + (bcd & 0x0F))
#define INT_BCD(i)				\
    (UCHAR)(((i / 10) << 4) + (i % 10))

#if defined(SARCH_XBOX)
/*
 * For some unknown reason the PIT of the Xbox is fixed at 1.125000 MHz,
 * which is ~5.7% lower than on the PC.
 */
#define PIT_FREQUENCY 1125000
#else
/*
 * Commonly stated as being 1.19318MHz
 *
 * See ISA System Architecture 3rd Edition (Tom Shanley, Don Anderson, John Swindle)
 * p. 471
 *
 * However, the true value is closer to 1.19318181[...]81MHz since this is 1/3rd
 * of the NTSC color subcarrier frequency which runs at 3.57954545[...]45MHz.
 *
 * Note that Windows uses 1.193167MHz which seems to have no basis. However, if
 * one takes the NTSC color subcarrier frequency as being 3.579545 (trimming the
 * infinite series) and divides it by three, one obtains 1.19318167.
 *
 * It may be that the original NT HAL source code introduced a typo and turned
 * 119318167 into 1193167 by ommitting the "18". This is very plausible as the
 * number is quite long.
 */
#define PIT_FREQUENCY 1193182
#endif

/*
 * These ports are controlled by the i8254 Programmable Interrupt Timer (PIT)
 */
#define TIMER_CHANNEL0_DATA_PORT 0x40
#define TIMER_CHANNEL1_DATA_PORT 0x41
#define TIMER_CHANNEL2_DATA_PORT 0x42
#define TIMER_CONTROL_PORT       0x43

/*
 * Mode 0 - Interrupt On Terminal Count
 * Mode 1 - Hardware Re-triggerable One-Shot
 * Mode 2 - Rate Generator
 * Mode 3 - Square Wave Generator
 * Mode 4 - Software Triggered Strobe
 * Mode 5 - Hardware Triggered Strobe
 */
typedef enum _TIMER_OPERATING_MODES {
    PitOperatingMode0,
    PitOperatingMode1,
    PitOperatingMode2,
    PitOperatingMode3,
    PitOperatingMode4,
    PitOperatingMode5,
    PitOperatingMode2Reserved,
    PitOperatingMode5Reserved
} TIMER_OPERATING_MODES;

typedef enum _TIMER_ACCESS_MODES {
    PitAccessModeCounterLatch,
    PitAccessModeLow,
    PitAccessModeHigh,
    PitAccessModeLowHigh
} TIMER_ACCESS_MODES;

typedef enum _TIMER_CHANNELS {
    PitChannel0,
    PitChannel1,
    PitChannel2,
    PitReadBack
} TIMER_CHANNELS;

typedef union _TIMER_CONTROL_PORT_REGISTER {
    struct {
        UCHAR BcdMode : 1;
        UCHAR OperatingMode : 3;
        UCHAR AccessMode : 2;
        UCHAR Channel : 2;
    };
    UCHAR Bits;
} TIMER_CONTROL_PORT_REGISTER, *PTIMER_CONTROL_PORT_REGISTER;

/*
 * See ISA System Architecture 3rd Edition (Tom Shanley, Don Anderson, John Swindle)
 * P. 400
 *
 * This port is controled by the i8255 Programmable Peripheral Interface (PPI)
 */
#define SYSTEM_CONTROL_PORT_A   0x92
#define SYSTEM_CONTROL_PORT_B   0x61
typedef union _SYSTEM_CONTROL_PORT_B_REGISTER {
    struct {
        UCHAR Timer2GateToSpeaker : 1;
        UCHAR SpeakerDataEnable : 1;
        UCHAR ParityCheckEnable : 1;
        UCHAR ChannelCheckEnable : 1;
        UCHAR RefreshRequest : 1;
        UCHAR Timer2Output : 1;
        UCHAR ChannelCheck : 1;
        UCHAR ParityCheck : 1;
    };
    UCHAR Bits;
} SYSTEM_CONTROL_PORT_B_REGISTER, *PSYSTEM_CONTROL_PORT_B_REGISTER;

/* CMOS Registers and Ports */
#define CMOS_CONTROL_PORT       0x70
#define CMOS_DATA_PORT          0x71
#define RTC_REGISTER_A          0x0A
#define   RTC_REG_A_UIP         0x80
#define RTC_REGISTER_B          0x0B
#define   RTC_REG_B_PI          0x40
#define RTC_REGISTER_C          0x0C
#define   RTC_REG_C_IRQ         0x80
#define RTC_REGISTER_D          0x0D
#define RTC_REGISTER_CENTURY    0x32

#define READ_PORT_UCHAR(PortNum)	__inbyte((ULONG_PTR)(PortNum))
#define WRITE_PORT_UCHAR(PortNum, Data)	__outbyte((ULONG_PTR)(PortNum), Data)

#define MAX_NUM_IOAPIC_PINS	256

typedef struct _HAL_IO_APIC {
    ULONG GlobalIrqBase;
    MWORD AssignedPins[MAX_NUM_IOAPIC_PINS / MWORD_BITS];
} HAL_IO_APIC, *PHAL_IO_APIC;

extern HAL_IO_APIC HalpIoApicTable[];

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

typedef struct _HAL_HPET {
    ULONG64 BaseAddress;  /* Base physical address of the MMIO region */
    BOOLEAN SystemTimer;  /* TRUE if this HPET is assigned as the system timer */
    UCHAR NumComparators; /* Total number of comparators of this timer */
    UCHAR ComparatorId;   /* Comparator ID in this HPET that is assigned as the system timer */
    ULONG TimerTick;	  /* Timer tick in units of femtoseconds (1e-15s) */
    ULONG64 Period;	  /* Period in units of femtoseconds (1e-15s) */
} HAL_HPET, *PHAL_HPET;

typedef struct _HAL_INTERRUPT_SOURCE_OVERRIDE {
    ULONG IrqSource;
    ULONG GlobalIrq;
    BOOLEAN LevelSensitive;
    BOOLEAN ActiveLow;
} HAL_INTERRUPT_SOURCE_OVERRIDE, *PHAL_INTERRUPT_SOURCE_OVERRIDE;

/* acpi.c */
NTSTATUS HalpInitAcpi(VOID);

/* init.c */
NTSTATUS HalpEnableIoPort(USHORT PortNum, USHORT Count);
UCHAR __inbyte(IN USHORT PortNum);
VOID __outbyte(IN USHORT PortNum,
	       IN UCHAR Data);

/* hpet.c */
NTSTATUS HalpEnableHpet(OUT PIRQ_HANDLER IrqHandler,
			IN ULONG64 Period);

/* pit.c */
NTSTATUS HalpInitPit(VOID);
NTSTATUS HalpEnablePit(OUT PIRQ_HANDLER IrqHandler,
		       IN ULONG64 Period);

#endif	/* defined(_M_IX86) || defined(_M_AMD64) */

#define NTOS_HAL_TAG	(EX_POOL_TAG('n','h','a','l'))

#define HalpAllocatePoolEx(Var, Type, OnError)				\
    ExAllocatePoolEx(Var, Type, sizeof(Type), NTOS_HAL_TAG, OnError)
#define HalpAllocatePool(Var, Type)	HalpAllocatePoolEx(Var, Type, {})
#define HalpAllocateArrayEx(Var, Type, Size, OnError)			\
    ExAllocatePoolEx(Var, Type, sizeof(Type) * (Size), NTOS_HAL_TAG, OnError)
#define HalpAllocateArray(Var, Type, Size)	\
    HalpAllocateArrayEx(Var, Type, Size, {})
#define HalpFreePool(Var) ExFreePoolWithTag(Var, NTOS_HAL_TAG)

/* dma.c */
NTSTATUS HalpInitDma(VOID);

/* rtc.c */
NTSTATUS HalpInitRtc(VOID);

/* smbios.c */
NTSTATUS HalpInitSmbios(VOID);
extern PCSTR HalpSmbiosStrings[SMBIOS_ID_STRINGS_MAX];

/* vga.c */
NTSTATUS HalpInitVga(VOID);
