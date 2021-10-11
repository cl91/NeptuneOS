#include <stdint.h>
#include "ldrp.h"
#include "cpio.h"

extern UCHAR _binary_initcpio_start[];
extern UCHAR _binary_initcpio_end[];
extern UCHAR _binary_initcpio_size[];

NTSTATUS LdrLoadBootModules()
{
    RET_ERR(ObCreateDirectory(BOOTMODULE_PARENT_DIRECTORY, BOOTMODULE_DIRECTORY));

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

    cpio_ls(_binary_initcpio_start, (size_t) _binary_initcpio_size,
	    FileNames, cpio.file_count);

    KeVgaWriteString("Available boot modules:");
    for (int i = 0; i < cpio.file_count; i++) {
	KeVgaPrint(" %s", FileNames[i]);
    }
    KeVgaWriteString("\n");

    for (int i = 0; i < cpio.file_count; i++) {
	SIZE_T FileSize;
	PCHAR FileContent = cpio_get_file(_binary_initcpio_start,
					  (size_t) _binary_initcpio_size,
					  FileNames[i], &FileSize);
	DbgTrace("File %s start vaddr %p size 0x%x\n", FileNames[i],
		 FileContent, (unsigned int) FileSize);

	/* Create FILE object and insert into object directory */
	PFILE_OBJECT File = NULL;
	RET_ERR(IoCreateFile(FileNames[i], (PVOID) FileContent, FileSize, &File));
	assert(File != NULL);
	RET_ERR_EX(ObInsertObjectByName(BOOTMODULE_PATH, File, FileNames[i]),
		   ObDeleteObject(File));
    }

    return STATUS_SUCCESS;
}
