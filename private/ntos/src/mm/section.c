#include "mi.h"

NTSTATUS MmCreateSection(OUT PVOID *SectionObject,
			 IN ACCESS_MASK DesiredAccess,
			 IN OPTIONAL PCHAR ObjectName,
			 IN MWORD InputMaxSize,
			 IN WIN32_PROTECTION_MASK SectionPageProtection,
			 IN ULONG AllocationAttributes,
			 IN OPTIONAL PFILE_OBJECT FileObject)
{
    return STATUS_SUCCESS;
}
