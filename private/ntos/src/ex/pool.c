#include <nt.h>
#include <ntos.h>

NTSTATUS ExInitializePool()
{
    return STATUS_SUCCESS;
}

PVOID ExAllocatePoolWithTag(IN ULONG NumberOfBytes,
			    IN USHORT Tag)
{
    return NULL;
}
