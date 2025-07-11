#include <pool.h>

ULONG RtlPoolAllocateNewPages(IN PRTL_SMALL_POOL Pool)
{
    PVOID BaseAddress = (PVOID)Pool->HeapEnd;
    SIZE_T CommitSize = PAGE_SIZE;
    NTSTATUS Status = NtAllocateVirtualMemory(NtCurrentProcess(),
					      &BaseAddress, 0, &CommitSize,
					      MEM_COMMIT, PAGE_READWRITE);
    if (!NT_SUCCESS(Status) || BaseAddress != (PVOID)Pool->HeapEnd) {
	return 0;
    }
    return CommitSize;
}
