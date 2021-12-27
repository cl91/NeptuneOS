#include <wdmp.h>

NTAPI NTSTATUS IoConnectInterrupt(OUT PKINTERRUPT *InterruptObject,
				  IN PKSERVICE_ROUTINE ServiceRoutine,
				  IN OPTIONAL PVOID ServiceContext,
				  IN ULONG Vector,
				  IN KIRQL Irql,
				  IN KIRQL SynchronizeIrql,
				  IN KINTERRUPT_MODE InterruptMode,
				  IN BOOLEAN ShareVector,
				  IN KAFFINITY ProcessorEnableMask,
				  IN BOOLEAN FloatingSave)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTAPI VOID IoDisconnectInterrupt(IN PKINTERRUPT InterruptObject)
{
}
