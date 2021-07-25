#include "iop.h"

NTSTATUS IopFileObjectCreateProc(POBJECT Object)
{
    PFILE_OBJECT File = (PFILE_OBJECT) Object;
    File->DeviceObject = NULL;
    File->FileName = NULL;
    File->SectionObject.DataSectionObject = NULL;
    File->SectionObject.ImageSectionObject = NULL;
    File->BufferPtr = 0;
    File->Size = 0;
    return STATUS_SUCCESS;
}

/*
 * For now FILE_OBJECT is just a pointer to an in-memory buffer.
 * Buffer must be aligned with 4K page boundary. Size is rounded up
 * to 4K page boundary.
 */
NTSTATUS IoCreateFile(IN PCSTR FileName,
		      IN MWORD BufferPtr,
		      IN MWORD FileSize,
		      OUT PFILE_OBJECT *pFile)
{
    assert(pFile != NULL);
    PFILE_OBJECT File = NULL;
    RET_ERR(ObCreateObject(OBJECT_TYPE_FILE, (POBJECT *) &File));
    assert(File != NULL);

    File->FileName = FileName;
    File->BufferPtr = BufferPtr;
    File->Size = FileSize;

    *pFile = File;
    return STATUS_SUCCESS;
}
