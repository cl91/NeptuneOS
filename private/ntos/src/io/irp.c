#include "iop.h"

NTSTATUS IopRequestIrp(IN PTHREAD Thread,
		       OUT ULONG *pNumIrp)
{
    assert(Thread != NULL);
    assert(pNumIrp != NULL);
    PIO_DRIVER_OBJECT DriverObject = Thread->Process->DriverObject;
    assert(DriverObject != NULL);

    KeSetEvent(&DriverObject->InitializationDoneEvent);
    ULONG NumIrp = 0;
    *pNumIrp = NumIrp;
    return STATUS_SUCCESS;
}
