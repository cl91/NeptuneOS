#include <nt.h>
#include <ntos.h>

NTSTATUS ExInitializePool()
{
    return STATUS_SUCCESS;
}

/* If request size > EX_POOL_BUDDY_MAX, return pages (use large pages if possible)
 * Else, allocate from the free list.
 * If no more space in free list, request one more page (use large page if available)
 * Each managed page is headed by EX_PAGE_DESCRIPTOR
 * Each unmanaged page has its EX_PAGE_DESCRIPTOR space allocated from the pool
 */
PVOID ExAllocatePoolWithTag(IN ULONG NumberOfBytes,
			    IN USHORT Tag)
{
    return NULL;
}
