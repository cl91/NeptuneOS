#pragma once

typedef struct _DEVICE_OBJECT {
    PCSTR DeviceName;
} DEVICE_OBJECT, *PDEVICE_OBJECT;

typedef struct _SECTION_OBJECT_POINTERS {
    PVOID DataSectionObject;
    PVOID ImageSectionObject;
} SECTION_OBJECT_POINTERS, *PSECTION_OBJECT_POINTERS;

typedef struct _FILE_OBJECT {
    PDEVICE_OBJECT DeviceObject;
    PCSTR FileName;
    PSECTION_OBJECT_POINTERS SectionObjectPointer;
} FILE_OBJECT, *PFILE_OBJECT;
