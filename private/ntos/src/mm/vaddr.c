/* Routines for virtual address space management */

#include "mi.h"

NTSTATUS MmReserveVirtualMemoryEx(IN PMM_VADDR_SPACE Vspace,
				  IN MWORD StartPageNum,
				  IN MWORD NumPages)
{
    if (MiVspaceFindVadNode(Vspace, StartPageNum, NumPages) != NULL) {
	/* Enlarge VAD? */
	return STATUS_NTOS_INVALID_ARGUMENT;
    }

    MiAllocatePool(Vad, MM_VAD);
    MiInitializeVadNode(Vad, StartPageNum, NumPages);
    MiVspaceInsertVadNode(Vspace, Vad);
    return STATUS_SUCCESS;
}

NTSTATUS MmReserveVirtualMemory(IN MWORD StartPageNum,
				IN MWORD NumPages)
{
    return MmReserveVirtualMemoryEx(&MiNtosVaddrSpace, StartPageNum, NumPages);
}
