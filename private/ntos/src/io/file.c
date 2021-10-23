#include "iop.h"

NTSTATUS IopFileObjectInitProc(POBJECT Object)
{
    PIO_FILE_OBJECT File = (PIO_FILE_OBJECT) Object;
    File->DeviceObject = NULL;
    File->FileName = NULL;
    File->SectionObject.DataSectionObject = NULL;
    File->SectionObject.ImageSectionObject = NULL;
    File->BufferPtr = 0;
    File->Size = 0;
    return STATUS_SUCCESS;
}

/*
 * For now IO_FILE_OBJECT is just a pointer to an in-memory buffer.
 * Buffer must be aligned with 4K page boundary. Size is rounded up
 * to 4K page boundary.
 */
NTSTATUS IoCreateFile(IN PCSTR FileName,
		      IN PVOID BufferPtr,
		      IN MWORD FileSize,
		      OUT PIO_FILE_OBJECT *pFile)
{
    assert(pFile != NULL);
    PIO_FILE_OBJECT File = NULL;
    RET_ERR(ObCreateObject(OBJECT_TYPE_FILE, (POBJECT *) &File));
    assert(File != NULL);

    File->FileName = FileName;
    File->BufferPtr = BufferPtr;
    File->Size = FileSize;

    *pFile = File;
    return STATUS_SUCCESS;
}

NTSTATUS IopFileObjectOpenProc(POBJECT Object)
{
    return STATUS_SUCCESS;
}

NTSTATUS NtCreateFile(IN PTHREAD Thread,
                      OUT HANDLE *FileHandle,
                      IN ACCESS_MASK DesiredAccess,
                      IN OB_OBJECT_ATTRIBUTES ObjectAttributes,
                      OUT IO_STATUS_BLOCK *IoStatusBlock,
                      IN OPTIONAL PLARGE_INTEGER AllocationSize,
                      IN ULONG FileAttributes,
                      IN ULONG ShareAccess,
                      IN ULONG CreateDisposition,
                      IN ULONG CreateOptions,
                      IN OPTIONAL PVOID EaBuffer,
                      IN ULONG EaLength)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtOpenFile(IN PTHREAD Thread,
                    OUT HANDLE *FileHandle,
                    IN ACCESS_MASK DesiredAccess,
                    IN OB_OBJECT_ATTRIBUTES ObjectAttributes,
                    OUT IO_STATUS_BLOCK *IoStatusBlock,
                    IN ULONG ShareAccess,
                    IN ULONG OpenOptions)
{
    return STATUS_NOT_IMPLEMENTED;
}

#ifdef CONFIG_DEBUG_BUILD
VOID IoDbgDumpFileObject(IN PIO_FILE_OBJECT File)
{
    DbgPrint("Dumping file object %p\n", File);
    if (File == NULL) {
	DbgPrint("    (nil)\n");
	return;
    }
    DbgPrint("    DeviceObject = %p\n", File->DeviceObject);
    DbgPrint("    FileName = %s\n", File->FileName);
    DbgPrint("    ImageSectionObject = %p\n", File->SectionObject.ImageSectionObject);
    DbgPrint("    DataSectionObject = %p\n", File->SectionObject.DataSectionObject);
    DbgPrint("    BufferPtr = %p\n", (PVOID) File->BufferPtr);
    DbgPrint("    Size = 0x%zx\n", File->Size);
}
#endif
