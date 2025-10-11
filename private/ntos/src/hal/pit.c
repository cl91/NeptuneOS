/*
 * Programmable Interval Timer support, including support for the pc speaker
 */

/* INCLUDES ******************************************************************/

#include "halp.h"

/* FUNCTIONS *****************************************************************/

#if defined(_M_IX86) || defined(_M_AMD64)

extern ULONG HalpNumInterruptSourceOverride;
extern HAL_INTERRUPT_SOURCE_OVERRIDE HalpInterruptSourceOverrideTable[];

/*
 * @implemented
 */
NTSTATUS WdmHalMakeBeep(IN ASYNC_STATE AsyncState,
			IN PTHREAD Thread,
			IN ULONG Frequency)
{
    DbgTrace("Frequency %d\n", Frequency);
    SYSTEM_CONTROL_PORT_B_REGISTER SystemControl;
    TIMER_CONTROL_PORT_REGISTER TimerControl;
    ULONG Divider;

    //
    // Turn the timer off by disconnecting its output pin and speaker gate
    //
    SystemControl.Bits = __inbyte(SYSTEM_CONTROL_PORT_B);
    SystemControl.SpeakerDataEnable = FALSE;
    SystemControl.Timer2GateToSpeaker = FALSE;
    __outbyte(SYSTEM_CONTROL_PORT_B, SystemControl.Bits);

    //
    // Check if we have a frequency
    //
    if (Frequency) {
	//
	// Set the divider
	//
	Divider = PIT_FREQUENCY / Frequency;

	//
	// Check if it's too large
	//
	if (Divider <= 0x10000) {
	    //
	    // Program the PIT for binary mode
	    //
	    TimerControl.BcdMode = FALSE;

	    //
	    // Program the PIT to generate a square wave (Mode 3) on channel 2.
	    // Channel 0 is used for the IRQ0 clock interval timer, and channel
	    // 1 is used for DRAM refresh.
	    //
	    // Mode 2 gives much better accuracy, but generates an output signal
	    // that drops to low for each input signal cycle at 0.8381 useconds.
	    // This is too fast for the PC speaker to process and would result
	    // in no sound being emitted.
	    //
	    // Mode 3 will generate a high pulse that is a bit longer and will
	    // allow the PC speaker to notice. Additionally, take note that on
	    // channel 2, when input goes low the counter will stop and output
	    // will go to high.
	    //
	    TimerControl.OperatingMode = PitOperatingMode3;
	    TimerControl.Channel = PitChannel2;

	    //
	    // Set the access mode that we'll use to program the reload value.
	    //
	    TimerControl.AccessMode = PitAccessModeLowHigh;

	    //
	    // Now write the programming bits
	    //
	    __outbyte(TIMER_CONTROL_PORT, TimerControl.Bits);

	    //
	    // Next we write the reload value for channel 2
	    //
	    __outbyte(TIMER_CHANNEL2_DATA_PORT, Divider & 0xFF);
	    __outbyte(TIMER_CHANNEL2_DATA_PORT, (Divider >> 8) & 0xFF);

	    //
	    // Reconnect the speaker to the timer and re-enable the output pin
	    //
	    SystemControl.Bits = __inbyte(SYSTEM_CONTROL_PORT_B);
	    SystemControl.SpeakerDataEnable = TRUE;
	    SystemControl.Timer2GateToSpeaker = TRUE;
	    __outbyte(SYSTEM_CONTROL_PORT_B, SystemControl.Bits);
	}
    }

    return STATUS_SUCCESS;
}

NTSTATUS HalpInitPit()
{
    RET_ERR(HalpEnableIoPort(TIMER_CHANNEL0_DATA_PORT, 1));
    RET_ERR(HalpEnableIoPort(TIMER_CHANNEL2_DATA_PORT, 1));
    RET_ERR(HalpEnableIoPort(TIMER_CONTROL_PORT, 1));
    RET_ERR(HalpEnableIoPort(SYSTEM_CONTROL_PORT_B, 1));
    return STATUS_SUCCESS;
}

NTSTATUS HalpEnablePit(OUT PIRQ_HANDLER IrqHandler,
		       IN ULONG64 Period)
{
    ULONG TableIndex = 0;
    while (TableIndex < HalpNumInterruptSourceOverride) {
	if (HalpInterruptSourceOverrideTable[TableIndex].IrqSource == 0) {
	    break;
	}
	TableIndex++;
    }
    assert(TableIndex <= HalpNumInterruptSourceOverride);
    if (TableIndex >= HalpNumInterruptSourceOverride) {
	assert(FALSE);
	return STATUS_NO_SUCH_DEVICE;
    }
    ULONG PitGlobalInterrupt = HalpInterruptSourceOverrideTable[TableIndex].GlobalIrq;

    NTSTATUS Status = HalAllocateIrq(PitGlobalInterrupt);
    if (!NT_SUCCESS(Status)) {
	assert(FALSE);
	DbgTrace("Failed to mask the IRQ pin for PIT\n");
	return Status;
    }

    ULONG Vector = ULONG_MAX;
    Status = IoAllocateInterruptVector(&Vector);
    if (!NT_SUCCESS(Status)) {
	assert(FALSE);
	HalDeallocateIrq(PitGlobalInterrupt);
	DbgTrace("Failed to allocate an IRQ vector for PIT\n");
	return Status;
    }
    assert(Vector != ULONG_MAX);
    /*
     * Program the PIT for binary mode, periodic, low-high byte writing, and on channel 0
     */
    TIMER_CONTROL_PORT_REGISTER TimerControl = {
	.BcdMode = FALSE,
	.OperatingMode = PitOperatingMode2,
	.AccessMode = PitAccessModeLowHigh,
	.Channel = PitChannel0
    };
    assert(TimerControl.Bits == 0x34);
    ULONG ReloadValue = Period * PIT_FREQUENCY / 10000000;
    if (ReloadValue < 1) {
	ReloadValue = 1;
    }
    if (ReloadValue > 0xFFFF) {
	ReloadValue = 0xFFFF;
    }
    __outbyte(TIMER_CONTROL_PORT, TimerControl.Bits);
    __outbyte(TIMER_CHANNEL0_DATA_PORT, ReloadValue & 0xFF);
    __outbyte(TIMER_CHANNEL0_DATA_PORT, (ReloadValue >> 8) & 0xFF);

    IrqHandler->Irq = PitGlobalInterrupt;
    IrqHandler->Vector = Vector;
    IrqHandler->Config.Word = 0;
    IrqHandler->Config.Level = HalpInterruptSourceOverrideTable[TableIndex].LevelSensitive;
    IrqHandler->Config.Polarity = HalpInterruptSourceOverrideTable[TableIndex].ActiveLow;
    IrqHandler->Message = 0;
    return STATUS_SUCCESS;
}

#else

NTSTATUS WdmHalMakeBeep(IN ASYNC_STATE AsyncState,
			IN PTHREAD Thread,
			IN ULONG Frequency)
{
    return STATUS_NOT_SUPPORTED;
}

#endif
