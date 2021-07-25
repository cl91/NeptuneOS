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

static NTSTATUS MiCreateImageFileMap(IN PFILE_OBJECT File,
				     OUT PSEGMENT *Segment)
{
    return STATUS_SUCCESS;
}

NTSTATUS MmCreateSection(IN PFILE_OBJECT FileObject,
			 IN MWORD Attribute,
			 OUT PSECTION *SectionObject)
{
    assert(FileObject != NULL);
    assert(SectionObject != NULL);
    *SectionObject = NULL;

    if (!(Attribute & SEC_FILE)) {
	return STATUS_NTOS_UNIMPLEMENTED;
    }

    if (!(Attribute & SEC_IMAGE)) {
	return STATUS_NTOS_UNIMPLEMENTED;
    }

    if (!(Attribute & SEC_RESERVE)) {
	return STATUS_NTOS_UNIMPLEMENTED;
    }

    if (!(Attribute & SEC_COMMIT)) {
	return STATUS_NTOS_UNIMPLEMENTED;
    }

    PSEGMENT Segment = FileObject->SectionObject.ImageSectionObject;

    if (Segment == NULL) {
	RET_ERR(MiCreateImageFileMap(FileObject, &Segment));
	assert(Segment != NULL);
	FileObject->SectionObject.ImageSectionObject = Segment;
    }

    PSECTION Section = NULL;
    RET_ERR(ObCreateObject(OBJECT_TYPE_SECTION, (POBJECT *) &Section));
    assert(Section != NULL);
    Section->Flags.File = 1;
    Section->Flags.Image = 1;
    /* For now all sections are committed immediately. */
    Section->Flags.Reserve = 1;
    Section->Flags.Commit = 1;
    Section->Segment = Segment;

    *SectionObject = Section;
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
