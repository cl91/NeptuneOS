#pragma once

#include <ntdef.h>
#include <ntseapi.h>

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
#define PAGE_WRITECOMBINE	(0x400)

#define MEM_COMMIT		(0x00001000UL)
#define MEM_RESERVE		(0x00002000UL)
#define MEM_DECOMMIT		(0x00004000UL)
#define MEM_RELEASE		(0x00008000UL)
#define MEM_FREE		(0x00010000UL)
#define MEM_PRIVATE		(0x00020000UL)
#define MEM_MAPPED		(0x00040000UL)
#define MEM_RESET		(0x00080000UL)
#define MEM_TOP_DOWN		(0x00100000UL)
#define MEM_WRITE_WATCH		(0x00200000UL)
#define MEM_PHYSICAL		(0x00400000UL)
#define MEM_LARGE_PAGES		(0x20000000UL)
/* This is a Neptune-OS specific extension, which is used to reserve
 * stack memory and commit them as they are accessed. Do not use in
 * user applications. */
#define MEM_COMMIT_ON_DEMAND	(0x80000000UL)

#define SEC_BASED		(0x00200000UL)
#define SEC_NO_CHANGE		(0x00400000UL)
#define SEC_FILE		(0x00800000UL)
#define SEC_IMAGE		(0x01000000UL)
#define SEC_RESERVE		(0x04000000UL)
#define SEC_COMMIT		(0x08000000UL)
#define SEC_NOCACHE		(0x10000000UL)
#define SEC_GLOBAL		(0x20000000UL)
#define SEC_LARGE_PAGES		(0x80000000UL)

typedef enum _MEMORY_CACHING_TYPE {
    MmNonCached = FALSE,
    MmCached = TRUE,
    MmFrameBufferCached = 2,
    MmWriteCombined = MmFrameBufferCached,
    MmHardwareCoherentCached,
    MmNonCachedUnordered,
    MmUSWCCached,
    MmMaximumCacheType
} MEMORY_CACHING_TYPE;

/*
 * Memory Information Classes for NtQueryVirtualMemory
 */
typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation,
    MemoryWorkingSetList,
    MemorySectionName,
    MemoryBasicVlmInformation,
    MemoryWorkingSetExList
} MEMORY_INFORMATION_CLASS;

/*
 * Memory Information Types
 */
typedef struct _MEMORY_BASIC_INFORMATION {
    PVOID BaseAddress;
    PVOID AllocationBase;
    ULONG AllocationProtect;
    SIZE_T RegionSize;
    ULONG State;
    ULONG Protect;
    ULONG Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

/*
 * Section Information Clasess for NtQuerySection
 */
typedef enum _SECTION_INFORMATION_CLASS {
    SectionBasicInformation,
    SectionImageInformation,
} SECTION_INFORMATION_CLASS;

/*
 * Section Information Structures for NtQuerySection
 */
typedef struct _SECTION_BASIC_INFORMATION {
    PVOID BaseAddress;
    ULONG Attributes;
    LARGE_INTEGER Size;
} SECTION_BASIC_INFORMATION, *PSECTION_BASIC_INFORMATION;

typedef struct _SECTION_IMAGE_INFORMATION {
    PVOID TransferAddress;
    ULONG ZeroBits;
    SIZE_T MaximumStackSize;
    SIZE_T CommittedStackSize;
    ULONG SubSystemType;
    union {
        struct {
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
	    UCHAR ComPlusNativeReady : 1;
	    UCHAR ComPlusILOnly : 1;
	    UCHAR ImageDynamicallyRelocated : 1;
	    UCHAR ImageMappedFlat : 1;
	    UCHAR Reserved : 4;
	};
	UCHAR ImageFlags;
    };			   /* Added in longhorn, was BOOLEAN Spare1 */
    ULONG LoaderFlags;
    ULONG ImageFileSize;
    ULONG CheckSum;	/* Added in longhorn, was ULONG Reserved[1] */
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;

/*
 * Section Inherit Flags for NtMapViewOfSection
 */
typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

/*
 * Section access rights
 */
#define SECTION_QUERY                0x0001
#define SECTION_MAP_WRITE            0x0002
#define SECTION_MAP_READ             0x0004
#define SECTION_MAP_EXECUTE          0x0008
#define SECTION_EXTEND_SIZE          0x0010
#define SECTION_MAP_EXECUTE_EXPLICIT 0x0020

#define SECTION_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SECTION_QUERY| \
                            SECTION_MAP_WRITE |                     \
                            SECTION_MAP_READ |                      \
                            SECTION_MAP_EXECUTE |                   \
                            SECTION_EXTEND_SIZE)

/*
 * Page-Rounding Macros
 */
#define PAGE_ROUND_DOWN(x)			\
    (((ULONG_PTR)(x))&(~(PAGE_SIZE-1)))
#define PAGE_ROUND_UP(x)					\
    ((((ULONG_PTR)(x)) + PAGE_SIZE-1) & (~(PAGE_SIZE-1)))

#ifndef _NTOSKRNL_

/*
 * Section-related routines
 */
NTAPI NTSYSAPI NTSTATUS NtCreateSection(OUT PHANDLE SectionHandle,
					IN ACCESS_MASK DesiredAccess,
					IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
					IN OPTIONAL PLARGE_INTEGER MaximumSize,
					IN ULONG SectionPageProtection,
					IN ULONG AllocationAttributes,
					IN OPTIONAL HANDLE FileHandle);

NTAPI NTSYSAPI NTSTATUS NtQuerySection(IN HANDLE SectionHandle,
				       IN SECTION_INFORMATION_CLASS SectionInformationClass,
				       OUT PVOID SectionInformation,
				       IN ULONG Length,
				       OUT OPTIONAL ULONG *pResultLength);

NTAPI NTSYSAPI NTSTATUS NtMapViewOfSection(IN HANDLE SectionHandle,
					   IN HANDLE ProcessHandle,
					   IN OUT PVOID *BaseAddress,
					   IN ULONG_PTR ZeroBits,
					   IN SIZE_T CommitSize,
					   IN OUT OPTIONAL PLARGE_INTEGER SectionOffset,
					   IN OUT PSIZE_T ViewSize,
					   IN SECTION_INHERIT InheritDisposition,
					   IN ULONG AllocationType,
					   IN ULONG AccessProtection);

NTAPI NTSYSAPI NTSTATUS NtUnmapViewOfSection(IN HANDLE ProcessHandle,
					     IN PVOID BaseAddress);

/*
 * Virtual memory management routines
 */
NTAPI NTSYSAPI NTSTATUS NtAllocateVirtualMemory(IN HANDLE ProcessHandle,
						IN OUT PVOID *BaseAddress,
						IN ULONG_PTR ZeroBits,
						IN OUT PSIZE_T RegionSize,
						IN ULONG AllocationType,
						IN ULONG Protect);

NTAPI NTSYSAPI NTSTATUS NtFreeVirtualMemory(IN HANDLE ProcessHandle,
					    IN OUT PVOID *BaseAddress,
					    IN OUT PSIZE_T RegionSize,
					    IN ULONG FreeType);

NTAPI NTSYSAPI NTSTATUS NtProtectVirtualMemory(IN HANDLE ProcessHandle,
					       IN PVOID *BaseAddress,
					       IN SIZE_T *NumberOfBytesToProtect,
					       IN ULONG NewAccessProtection,
					       OUT PULONG OldAccessProtection);

NTAPI NTSYSAPI NTSTATUS NtReadVirtualMemory(IN HANDLE ProcessHandle,
					    IN PVOID BaseAddress,
					    OUT PVOID Buffer,
					    IN SIZE_T NumberOfBytesToRead,
					    OUT OPTIONAL PSIZE_T NumberOfBytesRead);

NTAPI NTSYSAPI NTSTATUS NtWriteVirtualMemory(IN HANDLE ProcessHandle,
					     IN PVOID  BaseAddress,
					     IN PVOID Buffer,
					     IN SIZE_T NumberOfBytesToWrite,
					     OUT OPTIONAL PSIZE_T NumberOfBytesWritten);

#endif	/* _NTOSKRNL_ */
