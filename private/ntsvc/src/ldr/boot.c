#include <stdint.h>
#include <sel4/sel4.h>
#include <cpio/cpio.h>
#include <ntsvc.h>

extern UCHAR _binary_initcpio_start[];
extern UCHAR _binary_initcpio_end[];
extern UCHAR _binary_initcpio_size[];

#define NTSVC_LDR_BOOT_TAG	(EX_POOL_TAG('L', 'D', 'R', 'B'))

VOID LdrLoadBootModules()
{
    for (PUCHAR p = &_binary_initcpio_start[0]; p < &_binary_initcpio_end[0]; p++) {
    	if ((p - &_binary_initcpio_start[0]) % 8 == 0) {
    	    DbgPrint("\n");
    	}
    	DbgPrint("%02x ", *p, *p);
    }

    struct cpio_info cpio;
    cpio_info(_binary_initcpio_start, (size_t) _binary_initcpio_size, &cpio);
    DbgPrint("\ncpio has %d file(s):\n", cpio.file_count);
    PCHAR *FileNames = (PCHAR *) ExAllocatePoolWithTag(cpio.file_count, NTSVC_LDR_BOOT_TAG);
    if (FileNames == NULL) {
	KeBugCheckMsg("Out of memory.");
    }
    for (int i = 0; i < cpio.file_count; i++) {
	FileNames[i] = (PCHAR) ExAllocatePoolWithTag(cpio.max_path_sz+1, NTSVC_LDR_BOOT_TAG);
	if (FileNames[i] == NULL) {
	    KeBugCheckMsg("Out of memory.");
	}
    }
    cpio_ls(_binary_initcpio_start, (size_t) _binary_initcpio_size, FileNames, cpio.file_count);
    for (int i = 0; i < cpio.file_count; i++) {
	DbgPrint("  %s\n", FileNames[i]);
    }
    DbgPrint("Content of files:\n");
    for (int i = 0; i < cpio.file_count; i++) {
	DbgPrint("  %s:\n", FileNames[i]);
	MWORD FileSize;
	PCHAR FileContent = cpio_get_file(_binary_initcpio_start, (size_t) _binary_initcpio_size,
					  FileNames[i], &FileSize);
	for (int j = 0; j < FileSize; j++) {
	    DbgPrint("%c", FileContent[j]);
	}
    }
}
