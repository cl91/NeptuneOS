#include <hal.h>

PIO_REQUEST_PACKET IopIncomingIrpBuffer;
PIO_REQUEST_PACKET IopOutgoingIrpBuffer;

NTAPI VOID IoCompleteRequest(IN PIRP Irp,
			     IN CHAR PriorityBoost)
{
}
