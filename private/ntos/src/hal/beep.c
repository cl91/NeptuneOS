/*
 * PC Speaker support (beeping)
 */

/* INCLUDES ******************************************************************/

#include "halp.h"

/* FUNCTIONS *****************************************************************/

/*
 * @implemented
 */
NTSTATUS HalpMakeBeep(IN ASYNC_STATE AsyncState,
                      IN struct _THREAD *Thread,
                      IN ULONG Frequency)
{
    HalVgaPrint("HalpMakeBeep: Frequency %d\n", Frequency);
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

NTSTATUS HalpInitBeep()
{
    RET_ERR(HalpEnableIoPort(SYSTEM_CONTROL_PORT_B));
    RET_ERR(HalpEnableIoPort(TIMER_CONTROL_PORT));
    RET_ERR(HalpEnableIoPort(TIMER_CHANNEL2_DATA_PORT));
    return STATUS_SUCCESS;
}
