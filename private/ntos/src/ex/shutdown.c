#include "ei.h"

NTSTATUS NtShutdownSystem(IN ASYNC_STATE State,
                          IN SHUTDOWN_ACTION Action)
{
    NTSTATUS Status = STATUS_NTOS_BUG;

    ASYNC_BEGIN(State, Thread);
    HalVgaPrint("Syncing disks...\n");
    AWAIT(Status, IoShutdownSystem, State, _, Action);
    assert(NT_SUCCESS(Status));
    if (NT_SUCCESS(Status)) {
	/* The system doesn't seem to have the ability to turn itself off.
	 * We display a message and halt the system. */
	HalVgaPrint("\nIt is now safe to turn off your computer.\n");
	while (1) ;
    }
    ASYNC_END(State, Status);
}
