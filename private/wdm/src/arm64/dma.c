#include <wdmp.h>

NTAPI VOID KeFlushIoBuffers(IN PMDL Mdl,
			    IN BOOLEAN ReadOperation,
			    IN BOOLEAN DmaOperation)
{
    ULONG_PTR StartAddress = ALIGN_DOWN_BY(Mdl->MappedSystemVa,
					   SYSTEM_CACHE_ALIGNMENT_SIZE);
    ULONG_PTR EndAddress = ALIGN_UP_BY((ULONG_PTR)Mdl->MappedSystemVa + Mdl->ByteCount,
				       SYSTEM_CACHE_ALIGNMENT_SIZE);
    for (ULONG_PTR CurrentAddress = StartAddress; CurrentAddress < EndAddress;
	 CurrentAddress += SYSTEM_CACHE_ALIGNMENT_SIZE) {
	asm volatile ("dc cvau, %0\n" :: "r"(CurrentAddress));
    }
    asm volatile ("dsb sy" ::: "memory");
}
