#pragma once

#define NTOS_IO_TAG	(EX_POOL_TAG('n','t','i','o'))

typedef struct _DEVICE_OBJECT {
    PCSTR DeviceName;
} DEVICE_OBJECT, *PDEVICE_OBJECT;

typedef struct _SECTION_OBJECT_POINTERS {
    PSEGMENT DataSectionObject;
    PSEGMENT ImageSectionObject;
} SECTION_OBJECT_POINTERS, *PSECTION_OBJECT_POINTERS;

typedef struct _FILE_OBJECT {
    PDEVICE_OBJECT DeviceObject;
    PCSTR FileName;
    PSECTION_OBJECT_POINTERS SectionObject;
    MWORD BufferPtr;
    MWORD Size;
} FILE_OBJECT, *PFILE_OBJECT;

/*
 * Forward declarations.
 */

/* init.c */
NTSTATUS IoInitSystem();

/* create.c */
NTSTATUS IoCreateFile(IN PCSTR FileName,
		      IN MWORD BufferPtr,
		      IN MWORD FileSize,
		      OUT PFILE_OBJECT *pFile);
