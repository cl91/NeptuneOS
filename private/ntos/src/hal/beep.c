#include <ntos.h>

NTSTATUS HalpMakeBeep(IN ASYNC_STATE AsyncState,
                      IN struct _THREAD *Thread,
                      IN ULONG Frequency)
{
    if (Frequency != 0) {
	KeVgaPrint("Making beep with frequency %d\n", Frequency);
    } else {
	KeVgaPrint("Beep stopped\n");
    }
    return STATUS_SUCCESS;
}
