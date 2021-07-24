#include "mi.h"

NTSTATUS MiSectionObjectCreateProc(IN POBJECT Object)
{
    PSECTION Section = (PSECTION) Object;
    MiAvlInitializeNode(&Section->BasedSectionNode, 0);
    Section->Flags.Word = 0;
    Section->Segment = NULL;
    return STATUS_SUCCESS;
}

NTSTATUS MiSectionInitialization()
{
    OBJECT_TYPE_INITIALIZER TypeInfo = {
	.CreateProc = MiSectionObjectCreateProc,
	.OpenProc = NULL,
	.ParseProc = NULL,
	.InsertProc = NULL,
    };
    return ObCreateObjectType(OBJECT_TYPE_SECTION,
			      "Section",
			      sizeof(SECTION),
			      TypeInfo);
}

NTSTATUS MmCreateSection(OUT POBJECT *SectionObject,
			 IN ACCESS_MASK DesiredAccess,
			 IN OPTIONAL PCHAR ObjectName,
			 IN MWORD InputMaxSize,
			 IN WIN32_PROTECTION_MASK SectionPageProtection,
			 IN ULONG AllocationAttributes,
			 IN OPTIONAL PFILE_OBJECT FileObject)
{
    return STATUS_SUCCESS;
}

static NTSTATUS MiMapViewOfImageSection(IN PVIRT_ADDR_SPACE VSpace,
					IN PSECTION Section,
					IN OUT MWORD *BaseAddress,
					IN OUT MWORD *SectionOffset,
					IN OUT MWORD *ViewSize)
{
    return STATUS_SUCCESS;
}

/*
 * Map a view of the given section onto the given virtual address space.
 *
 * For now we commit the full view (CommitSize == ViewSize).
 */
NTSTATUS MmMapViewOfSection(IN PVIRT_ADDR_SPACE VSpace,
			    IN PSECTION Section,
			    IN OUT MWORD *BaseAddress,
			    IN OUT MWORD *SectionOffset,
			    IN OUT MWORD *ViewSize)
{
    assert(VSpace != NULL);
    assert(Section != NULL);
    if (Section->Flags.Image) {
	return MiMapViewOfImageSection(VSpace, Section, BaseAddress,
				       SectionOffset, ViewSize);
    }
    return STATUS_NTOS_UNIMPLEMENTED;
}
