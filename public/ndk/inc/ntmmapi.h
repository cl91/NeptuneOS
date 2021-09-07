#pragma once

#define PAGE_NOACCESS		(0x01)
#define PAGE_READONLY		(0x02)
#define PAGE_READWRITE		(0x04)
#define PAGE_WRITECOPY		(0x08)
#define PAGE_EXECUTE		(0x10)
#define PAGE_EXECUTE_READ	(0x20)
#define PAGE_EXECUTE_READWRITE	(0x40)
#define PAGE_EXECUTE_WRITECOPY	(0x80)
#define PAGE_GUARD		(0x100)
#define PAGE_NOCACHE		(0x200)

#define MEM_COMMIT		(0x00001000UL)
#define MEM_RESERVE		(0x00002000UL)
#define MEM_DECOMMIT		(0x00004000UL)
#define MEM_RELEASE		(0x00008000UL)
#define MEM_FREE		(0x00010000UL)
#define MEM_PRIVATE		(0x00020000UL)
#define MEM_MAPPED		(0x00040000UL)
#define MEM_TOP_DOWN		(0x00100000UL)
#define MEM_LARGE_PAGES		(0x20000000UL)

#define SEC_BASED		(0x00200000UL)
#define SEC_NO_CHANGE		(0x00400000UL)
#define SEC_FILE		(0x00800000UL)
#define SEC_IMAGE		(0x01000000UL)
#define SEC_RESERVE		(0x04000000UL)
#define SEC_COMMIT		(0x08000000UL)
#define SEC_NOCACHE		(0x10000000UL)
#define SEC_GLOBAL		(0x20000000UL)
#define SEC_LARGE_PAGES		(0x80000000UL)

typedef struct _SECTION_IMAGE_INFORMATION {
    PVOID TransferAddress;
    ULONG ZeroBits;
    SIZE_T MaximumStackSize;
    SIZE_T CommittedStackSize;
    ULONG SubSystemType;
    union
    {
        struct
        {
            USHORT SubSystemMinorVersion;
            USHORT SubSystemMajorVersion;
        };
        ULONG SubSystemVersion;
    };
    ULONG GpValue;
    USHORT ImageCharacteristics;
    USHORT DllCharacteristics;
    USHORT Machine;
    BOOLEAN ImageContainsCode;
    union {
	struct {
	    UCHAR ComPlusNativeReady:1;
	    UCHAR ComPlusILOnly:1;
	    UCHAR ImageDynamicallyRelocated:1;
	    UCHAR ImageMappedFlat:1;
	    UCHAR Reserved:4;
	};
	UCHAR ImageFlags;
    };			   /* Added in longhorn, was BOOLEAN Spare1 */
    ULONG LoaderFlags;
    ULONG ImageFileSize;
    ULONG CheckSum;	/* Added in longhorn, was ULONG Reserved[1] */
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;
