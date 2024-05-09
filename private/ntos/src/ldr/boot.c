#include <stdint.h>
#include "ldrp.h"
#include "cpio.h"

extern UCHAR _binary_initcpio_start[];
extern UCHAR _binary_initcpio_end[];
extern UCHAR _binary_initcpio_size[];

static VOID LdrpPinDataCallback(IN PIO_FILE_CONTROL_BLOCK Fcb,
				IN ULONG64 FileOffset,
				IN ULONG64 Length,
				IN NTSTATUS Status,
				IN OUT PVOID Context)
{
    if (NT_SUCCESS(Status)) {
	Status = CcCopyWrite(Fcb, 0, Length, Context);
    }
    if (!NT_SUCCESS(Status)) {
	KeBugCheckMsg("Failed to load boot module (address %p), error = 0x%x\n",
		      Context, Status);
    }
}

NTSTATUS LdrLoadBootModules()
{
    RET_ERR(ObCreateDirectory(DOS_DEVICES_DIRECTORY));
    RET_ERR(ObCreateDirectory(BOOT_MODULES_DIRECTORY));
    POBJECT BootModulesDirectory = NULL;
    RET_ERR(ObReferenceObjectByName(BOOT_MODULES_DIRECTORY, OBJECT_TYPE_DIRECTORY,
				    NULL, FALSE, &BootModulesDirectory));
    assert(BootModulesDirectory != NULL);
    PIO_FILE_OBJECT BootModulesDirectoryFile = NULL;
    /* Create a dummy FILE object for the boot modules directory so at the very
     * early stage of the boot process (before any file system is mounted), ntdll
     * can get a valid handle for the boot modules directory. */
    RET_ERR(IoCreateDevicelessFile(".", BootModulesDirectory, 0,
				   FILE_ATTRIBUTE_DIRECTORY, &BootModulesDirectoryFile));

    struct cpio_info cpio;
    int error = cpio_info(_binary_initcpio_start, (size_t) _binary_initcpio_size, &cpio);
    if (error) {
	return STATUS_INVALID_IMAGE_FORMAT;
    }
    DbgTrace("initcpio has %d file(s).\n", cpio.file_count);

    LdrpAllocateArray(FileNames, PCHAR, cpio.file_count);

    for (int i = 0; i < cpio.file_count; i++) {
	LdrpAllocateArray(FileName, CHAR, cpio.max_path_sz+1);
	FileNames[i] = FileName;
    }

    cpio_ls(_binary_initcpio_start, (size_t)_binary_initcpio_size,
	    FileNames, cpio.file_count);

    HalDisplayString("Available boot modules:");
    for (int i = 0; i < cpio.file_count; i++) {
	HalVgaPrint(" %s", FileNames[i]);
    }
    HalDisplayString("\n");

    for (int i = 0; i < cpio.file_count; i++) {
	SIZE_T FileSize;
	PCHAR FileContent = cpio_get_file(_binary_initcpio_start,
					  (size_t)_binary_initcpio_size,
					  FileNames[i], &FileSize);
	DbgTrace("File %s start vaddr %p size 0x%x\n", FileNames[i],
		 FileContent, (unsigned int) FileSize);

	PIO_FILE_OBJECT File = NULL;
	/* Create the FILE object and insert into the object directory */
	RET_ERR(IoCreateDevicelessFile(FileNames[i], BootModulesDirectory,
				       FileSize, 0, &File));
	assert(File);
	assert(File->Fcb);
	CcPinDataEx(File->Fcb, 0, FileSize, FALSE, LdrpPinDataCallback, FileContent);
    }
    ObDereferenceObject(BootModulesDirectory);

    return STATUS_SUCCESS;
}
