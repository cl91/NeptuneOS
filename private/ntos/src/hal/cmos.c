/*
 * PROJECT:         ReactOS HAL
 * LICENSE:         GPL - See COPYING in the top level directory
 * PURPOSE:         CMOS Access Routines (Real Time Clock and LastKnownGood)
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 *                  Eric Kohl
 */

/* INCLUDES ******************************************************************/

#include "halp.h"

/* GLOBALS *******************************************************************/

static X86_IOPORT HalpCmosControlPort;
static X86_IOPORT HalpCmosDataPort;

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

/* PRIVATE FUNCTIONS *********************************************************/

static UCHAR HalpReadCmos(IN UCHAR Reg)
{
    /* Select the register */
    KeWritePort8(&HalpCmosControlPort, Reg);

    /* Query the value */
    UCHAR Value = 0;
    KeReadPort8(&HalpCmosDataPort, &Value);
    return Value;
}

static VOID HalpWriteCmos(IN UCHAR Reg,
			  IN UCHAR Value)
{
    /* Select the register */
    KeWritePort8(&HalpCmosControlPort, Reg);

    /* Write the value */
    KeWritePort8(&HalpCmosDataPort, Value);
}

static ULONG HalpGetCmosData(IN ULONG BusNumber,
			     IN ULONG SlotNumber,
			     OUT PVOID Buffer,
			     IN ULONG Length)
{
    PUCHAR Ptr = (PUCHAR) Buffer;
    ULONG Address = SlotNumber;
    ULONG Len = Length;

    /* Do nothing if we don't have a length */
    if (!Length)
	return 0;

    /* Check if this is simple CMOS */
    if (BusNumber == 0) {
	/* Loop the buffer up to 0xFF */
	while ((Len > 0) && (Address < 0x100)) {
	    /* Read the data */
	    *Ptr = HalpReadCmos((UCHAR) Address);

	    /* Update position and length */
	    Ptr++;
	    Address++;
	    Len--;
	}
    } else if (BusNumber == 1) {
	/* Loop the buffer up to 0xFFFF */
	while ((Len > 0) && (Address < 0x10000)) {
	    /* Write the data */
	    *Ptr = HalpReadCmos((UCHAR) Address);

	    /* Update position and length */
	    Ptr++;
	    Address++;
	    Len--;
	}
    }

    /* Return length read */
    return Length - Len;
}

static ULONG HalpSetCmosData(IN ULONG BusNumber,
			     IN ULONG SlotNumber,
			     IN PVOID Buffer,
			     IN ULONG Length)
{
    PUCHAR Ptr = (PUCHAR) Buffer;
    ULONG Address = SlotNumber;
    ULONG Len = Length;

    /* Do nothing if we don't have a length */
    if (!Length)
	return 0;

    /* Check if this is simple CMOS */
    if (BusNumber == 0) {
	/* Loop the buffer up to 0xFF */
	while ((Len > 0) && (Address < 0x100)) {
	    /* Write the data */
	    HalpWriteCmos((UCHAR) Address, *Ptr);

	    /* Update position and length */
	    Ptr++;
	    Address++;
	    Len--;
	}
    } else if (BusNumber == 1) {
	/* Loop the buffer up to 0xFFFF */
	while ((Len > 0) && (Address < 0x10000)) {
	    /* Write the data */
	    HalpWriteCmos((UCHAR) Address, *Ptr);

	    /* Update position and length */
	    Ptr++;
	    Address++;
	    Len--;
	}
    }

    /* Return length read */
    return Length - Len;
}

/* PUBLIC FUNCTIONS **********************************************************/

NTSTATUS HalInitializeCmos(VOID)
{
    RET_ERR(KeEnableIoPort(CMOS_CONTROL_PORT, &HalpCmosControlPort));
    RET_ERR(KeEnableIoPort(CMOS_DATA_PORT, &HalpCmosDataPort));
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
BOOLEAN HalQueryRealTimeClock(OUT PTIME_FIELDS Time)
{
    /* Loop while update is in progress */
    while ((HalpReadCmos(RTC_REGISTER_A)) & RTC_REG_A_UIP);

    /* Set the time data */
    Time->Second = BCD_INT(HalpReadCmos(0));
    Time->Minute = BCD_INT(HalpReadCmos(2));
    Time->Hour = BCD_INT(HalpReadCmos(4));
    Time->Weekday = BCD_INT(HalpReadCmos(6));
    Time->Day = BCD_INT(HalpReadCmos(7));
    Time->Month = BCD_INT(HalpReadCmos(8));
    Time->Year = BCD_INT(HalpReadCmos(9));
    Time->Milliseconds = 0;

    /* FIXME: Check century byte */

    /* Compensate for the century field */
    Time->Year += (Time->Year > 80) ? 1900 : 2000;

    /* Always return TRUE */
    return TRUE;
}

/*
 * @implemented
 */
BOOLEAN HalSetRealTimeClock(IN PTIME_FIELDS Time)
{
    /* Loop while update is in progress */
    while ((HalpReadCmos(RTC_REGISTER_A)) & RTC_REG_A_UIP);

    /* Write time fields to CMOS RTC */
    HalpWriteCmos(0, INT_BCD(Time->Second));
    HalpWriteCmos(2, INT_BCD(Time->Minute));
    HalpWriteCmos(4, INT_BCD(Time->Hour));
    HalpWriteCmos(6, INT_BCD(Time->Weekday));
    HalpWriteCmos(7, INT_BCD(Time->Day));
    HalpWriteCmos(8, INT_BCD(Time->Month));
    HalpWriteCmos(9, INT_BCD(Time->Year % 100));

    /* FIXME: Set the century byte */

    /* Always return TRUE */
    return TRUE;
}
