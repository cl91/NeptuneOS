#include <stdint.h>
#include <ntos.h>
#include "cpio.h"

extern UCHAR _binary_initcpio_start[];
extern UCHAR _binary_initcpio_end[];
extern UCHAR _binary_initcpio_size[];

#define NTOS_LDR_BOOT_TAG	(EX_POOL_TAG('L', 'D', 'R', 'B'))

#define LdrpAllocatePoolEx(Var, Type, OnError)				\
    ExAllocatePoolEx(Var, Type, sizeof(Type), NTOS_LDR_BOOT_TAG, OnError)
#define LdrpAllocatePool(Var, Type)	LdrpAllocatePoolEx(Var, Type, {})
#define LdrpAllocateArray(Var, Type, Size)				\
    ExAllocatePoolEx(Var, Type, sizeof(Type) * (Size), NTOS_LDR_BOOT_TAG, {})

NTSTATUS LdrLoadBootModules()
{
    RET_ERR(ObCreateDirectory("\\", "BootModules"));

    struct cpio_info cpio;
    cpio_info(_binary_initcpio_start, (size_t) _binary_initcpio_size, &cpio);
    DbgTrace("initcpio has %d file(s).\n", cpio.file_count);

    LdrpAllocateArray(FileNames, PCHAR, cpio.file_count);

    for (int i = 0; i < cpio.file_count; i++) {
	LdrpAllocateArray(FileName, CHAR, cpio.max_path_sz+1);
	FileNames[i] = FileName;
    }

    cpio_ls(_binary_initcpio_start, (size_t) _binary_initcpio_size,
	    FileNames, cpio.file_count);

    DbgTrace("initcpio file list:\n");
    for (int i = 0; i < cpio.file_count; i++) {
	DbgPrint("    %s\n", FileNames[i]);
    }

    MWORD CurAddr = BOOT_MODULES_START;
    for (int i = 0; i < cpio.file_count; i++) {
	SIZE_T FileSize;
	PCHAR FileContent = cpio_get_file(_binary_initcpio_start,
					  (size_t) _binary_initcpio_size,
					  FileNames[i], &FileSize);
	DbgTrace("File %s start vaddr %p size 0x%x\n", FileNames[i],
		 FileContent, (unsigned int) FileSize);

	/* Request pages from mm and copy file content over. */
	MWORD CommitSize = PAGE_ALIGN(FileSize + PAGE_SIZE - 1);
	if (CurAddr + CommitSize >= BOOT_MODULES_START + BOOT_MODULES_MAX_SIZE) {
	    break;
	}
	RET_ERR(MmAllocatePrivateMemory(CurAddr, CommitSize));
	memcpy((PVOID) CurAddr, FileContent, FileSize);

	/* Create FILE object and insert into object directory */
	PFILE_OBJECT File = NULL;
	RET_ERR(IoCreateFile(FileNames[i], CurAddr, FileSize, &File));
	assert(File != NULL);
	CurAddr += CommitSize;
	RET_ERR_EX(ObInsertObjectByName("\\BootModules", File, FileNames[i]),
		   ObDereferenceObject(File));
    }

    return STATUS_SUCCESS;
}
