/*
 * Runtime library types and functions exported by NTDLL.
 * These are not defined for the NTOS root task.
 */

#pragma once

#ifdef _NTOSKRNL_
#error "Do not include <nturtl.h> for the NTOS root task"
#endif

#include <ntmmapi.h>
#include <ntpsapi.h>
#include <ntseapi.h>

typedef struct _COMPRESSED_DATA_INFO {
    USHORT CompressionFormatAndEngine;
    UCHAR CompressionUnitShift;
    UCHAR ChunkShift;
    UCHAR ClusterShift;
    UCHAR Reserved;
    USHORT NumberOfChunks;
    ULONG CompressedChunkSizes[ANYSIZE_ARRAY];
} COMPRESSED_DATA_INFO, *PCOMPRESSED_DATA_INFO;

typedef struct _RTL_USER_PROCESS_INFORMATION {
    ULONG Size;
    HANDLE ProcessHandle;
    HANDLE ThreadHandle;
    CLIENT_ID ClientId;
    SECTION_IMAGE_INFORMATION ImageInformation;
} RTL_USER_PROCESS_INFORMATION, *PRTL_USER_PROCESS_INFORMATION;

/*
 * Process Parameters Flags
 */
#define RTL_USER_PROCESS_PARAMETERS_NORMALIZED              0x01
#define RTL_USER_PROCESS_PARAMETERS_PROFILE_USER            0x02
#define RTL_USER_PROCESS_PARAMETERS_PROFILE_KERNEL          0x04
#define RTL_USER_PROCESS_PARAMETERS_PROFILE_SERVER          0x08
#define RTL_USER_PROCESS_PARAMETERS_UNKNOWN                 0x10
#define RTL_USER_PROCESS_PARAMETERS_RESERVE_1MB             0x20
#define RTL_USER_PROCESS_PARAMETERS_RESERVE_16MB            0x40
#define RTL_USER_PROCESS_PARAMETERS_CASE_SENSITIVE          0x80
#define RTL_USER_PROCESS_PARAMETERS_DISABLE_HEAP_CHECKS     0x100
#define RTL_USER_PROCESS_PARAMETERS_PROCESS_OR_1            0x200
#define RTL_USER_PROCESS_PARAMETERS_PROCESS_OR_2            0x400
#define RTL_USER_PROCESS_PARAMETERS_PRIVATE_DLL_PATH        0x1000
#define RTL_USER_PROCESS_PARAMETERS_LOCAL_DLL_PATH          0x2000
#define RTL_USER_PROCESS_PARAMETERS_IMAGE_KEY_MISSING       0x4000
#define RTL_USER_PROCESS_PARAMETERS_NX                      0x20000

/*
 * Thread and Process Start Routines for RtlCreateUserThread/Process
 */
typedef ULONG (NTAPI *PTHREAD_START_ROUTINE)(PVOID Parameter);

/*
 * End of Exception List
 */
#define EXCEPTION_CHAIN_END		((PEXCEPTION_REGISTRATION_RECORD)-1)

/*
 * Unhandled Exception Filter
 */
typedef ULONG (NTAPI *RTLP_UNHANDLED_EXCEPTION_FILTER)(IN struct _EXCEPTION_POINTERS *ExceptionInfo);
typedef RTLP_UNHANDLED_EXCEPTION_FILTER *PRTLP_UNHANDLED_EXCEPTION_FILTER;

/*
 * Handler during Vectored RTL Exceptions
 */
typedef LONG (NTAPI *PVECTORED_EXCEPTION_HANDLER)(PEXCEPTION_POINTERS ExceptionPointers);

/*
 * Fiber local storage data
 */
#define RTL_FLS_MAXIMUM_AVAILABLE 128
typedef struct _RTL_FLS_DATA
{
    LIST_ENTRY ListEntry;
    PVOID Data[RTL_FLS_MAXIMUM_AVAILABLE];
} RTL_FLS_DATA, *PRTL_FLS_DATA;

/*
 * Thread local storage slots
 */
#define TLS_MINIMUM_AVAILABLE 64
#define TLS_EXPANSION_SLOTS 1024

/*
 * Thread Error Mode Flags
 */
/* Also defined in psdk/winbase.h */
#define SEM_FAILCRITICALERRORS          0x0001
#define SEM_NOGPFAULTERRORBOX           0x0002
#define SEM_NOALIGNMENTFAULTEXCEPT      0x0004
#define SEM_NOOPENFILEERRORBOX          0x8000

#define RTL_SEM_FAILCRITICALERRORS      (SEM_FAILCRITICALERRORS     << 4)
#define RTL_SEM_NOGPFAULTERRORBOX       (SEM_NOGPFAULTERRORBOX      << 4)
#define RTL_SEM_NOALIGNMENTFAULTEXCEPT  (SEM_NOALIGNMENTFAULTEXCEPT << 4)

/*
 * Public Heap Flags
 */
#define HEAP_NO_SERIALIZE                                   0x00000001
#define HEAP_GROWABLE                                       0x00000002
#define HEAP_GENERATE_EXCEPTIONS                            0x00000004
#define HEAP_ZERO_MEMORY                                    0x00000008
#define HEAP_REALLOC_IN_PLACE_ONLY                          0x00000010
#define HEAP_TAIL_CHECKING_ENABLED                          0x00000020
#define HEAP_FREE_CHECKING_ENABLED                          0x00000040
#define HEAP_DISABLE_COALESCE_ON_FREE                       0x00000080
#define HEAP_CREATE_ALIGN_16                                0x00010000
#define HEAP_CREATE_ENABLE_TRACING                          0x00020000
#define HEAP_CREATE_ENABLE_EXECUTE                          0x00040000

/*
 * User-Defined Heap Flags and Classes
 */
#define HEAP_SETTABLE_USER_VALUE                            0x00000100
#define HEAP_SETTABLE_USER_FLAG1                            0x00000200
#define HEAP_SETTABLE_USER_FLAG2                            0x00000400
#define HEAP_SETTABLE_USER_FLAG3                            0x00000800
#define HEAP_SETTABLE_USER_FLAGS                            0x00000E00
#define HEAP_CLASS_0                                        0x00000000
#define HEAP_CLASS_1                                        0x00001000
#define HEAP_CLASS_2                                        0x00002000
#define HEAP_CLASS_3                                        0x00003000
#define HEAP_CLASS_4                                        0x00004000
#define HEAP_CLASS_5                                        0x00005000
#define HEAP_CLASS_6                                        0x00006000
#define HEAP_CLASS_7                                        0x00007000
#define HEAP_CLASS_8                                        0x00008000
#define HEAP_CLASS_MASK                                     0x0000F000

/*
 * Internal HEAP Structure Flags
 */
#define HEAP_FLAG_PAGE_ALLOCS                               0x01000000
#define HEAP_PROTECTION_ENABLED                             0x02000000
#define HEAP_BREAK_WHEN_OUT_OF_VM                           0x04000000
#define HEAP_NO_ALIGNMENT                                   0x08000000
#define HEAP_CAPTURE_STACK_BACKTRACES                       0x08000000
#define HEAP_SKIP_VALIDATION_CHECKS                         0x10000000
#define HEAP_VALIDATE_ALL_ENABLED                           0x20000000
#define HEAP_VALIDATE_PARAMETERS_ENABLED                    0x40000000
#define HEAP_LOCK_USER_ALLOCATED                            0x80000000

/*
 * Heap Validation Flags
 */
#define HEAP_CREATE_VALID_MASK			\
    (HEAP_NO_SERIALIZE              |		\
     HEAP_GROWABLE                  |		\
     HEAP_GENERATE_EXCEPTIONS       |		\
     HEAP_ZERO_MEMORY               |		\
     HEAP_REALLOC_IN_PLACE_ONLY     |		\
     HEAP_TAIL_CHECKING_ENABLED     |		\
     HEAP_FREE_CHECKING_ENABLED     |		\
     HEAP_DISABLE_COALESCE_ON_FREE  |		\
     HEAP_CLASS_MASK                |		\
     HEAP_CREATE_ALIGN_16           |		\
     HEAP_CREATE_ENABLE_TRACING     |		\
     HEAP_CREATE_ENABLE_EXECUTE)

#define HEAP_MAXIMUM_TAG                0x0FFF
#define HEAP_GLOBAL_TAG                 0x0800
#define HEAP_PSEUDO_TAG_FLAG            0x8000
#define HEAP_TAG_SHIFT                  18
#define HEAP_TAG_MASK                   (HEAP_MAXIMUM_TAG << HEAP_TAG_SHIFT)

/*
 * Custom Heap Commit Routine for RtlCreateHeap
 */
typedef NTSTATUS (NTAPI *PRTL_HEAP_COMMIT_ROUTINE)(IN PVOID Base,
						   IN OUT PVOID *CommitAddress,
						   IN OUT PSIZE_T CommitSize);

/*
 * Callback for RTL Heap Enumeration
 */
typedef NTSTATUS (NTAPI *PHEAP_ENUMERATION_ROUTINE)(IN PVOID HeapHandle,
						    IN PVOID UserParam);

/*
 * Parameters for RtlCreateHeap
 */
typedef struct _RTL_HEAP_PARAMETERS {
    ULONG Length;
    SIZE_T SegmentReserve;
    SIZE_T SegmentCommit;
    SIZE_T DeCommitFreeBlockThreshold;
    SIZE_T DeCommitTotalFreeThreshold;
    SIZE_T MaximumAllocationSize;
    SIZE_T VirtualMemoryThreshold;
    SIZE_T InitialCommit;
    SIZE_T InitialReserve;
    PRTL_HEAP_COMMIT_ROUTINE CommitRoutine;
    SIZE_T Reserved[2];
} RTL_HEAP_PARAMETERS, *PRTL_HEAP_PARAMETERS;

/*
 * Information returned by RtlUsageHeap
 */
typedef struct _RTL_HEAP_USAGE_ENTRY {
    struct _RTL_HEAP_USAGE_ENTRY *Next;
    PVOID Address;
    SIZE_T Size;
    USHORT AllocatorBackTraceIndex;
    USHORT TagIndex;
} RTL_HEAP_USAGE_ENTRY, *PRTL_HEAP_USAGE_ENTRY;

typedef struct _RTL_HEAP_USAGE {
    ULONG Length;
    SIZE_T BytesAllocated;
    SIZE_T BytesCommitted;
    SIZE_T BytesReserved;
    SIZE_T BytesReservedMaximum;
    PRTL_HEAP_USAGE_ENTRY Entries;
    PRTL_HEAP_USAGE_ENTRY AddedEntries;
    PRTL_HEAP_USAGE_ENTRY RemovedEntries;
    ULONG_PTR Reserved[8];
} RTL_HEAP_USAGE, *PRTL_HEAP_USAGE;

/*
 * Information returned by RtlQueryTagHeap
 */
typedef struct _RTL_HEAP_TAG_INFO {
    ULONG NumberOfAllocations;
    ULONG NumberOfFrees;
    SIZE_T BytesAllocated;
} RTL_HEAP_TAG_INFO, *PRTL_HEAP_TAG_INFO;

/*
 * Heap Information Class
 */
typedef enum _HEAP_INFORMATION_CLASS {
    HeapCompatibilityInformation,
    HeapEnableTerminationOnCorruption
} HEAP_INFORMATION_CLASS;

/*
 * Singly Linked Lists
 */
typedef struct _SINGLE_LIST_ENTRY {
    struct _SINGLE_LIST_ENTRY *Next;
} SINGLE_LIST_ENTRY, *PSINGLE_LIST_ENTRY;

/*
 * Interlocked sequenced list
 */
#ifdef _WIN64

typedef struct DECLSPEC_ALIGN(16) _SLIST_ENTRY {
    struct _SLIST_ENTRY *Next;
} SLIST_ENTRY, *PSLIST_ENTRY;

typedef struct _SLIST_ENTRY32 {
    ULONG Next;
} SLIST_ENTRY32, *PSLIST_ENTRY32;

typedef union DECLSPEC_ALIGN(16) _SLIST_HEADER {
    _ANONYMOUS_STRUCT struct {
	ULONGLONG Alignment;
	ULONGLONG Region;
    } DUMMYSTRUCTNAME;
    struct {
	ULONGLONG Depth:16;
	ULONGLONG Sequence:9;
	ULONGLONG NextEntry:39;
	ULONGLONG HeaderType:1;
	ULONGLONG Init:1;
	ULONGLONG Reserved:59;
	ULONGLONG Region:3;
    } Header8;
    struct {
	ULONGLONG Depth:16;
	ULONGLONG Sequence:48;
	ULONGLONG HeaderType:1;
	ULONGLONG Init:1;
	ULONGLONG Reserved:2;
	ULONGLONG NextEntry:60;
    } Header16;
    struct {
	ULONGLONG Depth:16;
	ULONGLONG Sequence:48;
	ULONGLONG HeaderType:1;
	ULONGLONG Reserved:3;
	ULONGLONG NextEntry:60;
    } HeaderX64;
} SLIST_HEADER, *PSLIST_HEADER;

typedef union _SLIST_HEADER32 {
    ULONGLONG Alignment;
    _ANONYMOUS_STRUCT struct {
	SLIST_ENTRY32 Next;
	USHORT Depth;
	USHORT Sequence;
    } DUMMYSTRUCTNAME;
} SLIST_HEADER32, *PSLIST_HEADER32;

#else  /* WIN32 */

#define SLIST_ENTRY SINGLE_LIST_ENTRY
#define _SLIST_ENTRY _SINGLE_LIST_ENTRY
#define PSLIST_ENTRY PSINGLE_LIST_ENTRY

typedef SLIST_ENTRY SLIST_ENTRY32, *PSLIST_ENTRY32;

typedef union _SLIST_HEADER {
    ULONGLONG Alignment;
    _ANONYMOUS_STRUCT struct {
	SLIST_ENTRY Next;
	USHORT Depth;
	USHORT Sequence;
    } DUMMYSTRUCTNAME;
} SLIST_HEADER, *PSLIST_HEADER;

typedef SLIST_HEADER SLIST_HEADER32, *PSLIST_HEADER32;

#endif /* defined(_WIN64) */

/*
 * RTL Splay and Balanced Links (AVL tree) structures
 */
typedef struct _RTL_SPLAY_LINKS {
    struct _RTL_SPLAY_LINKS *Parent;
    struct _RTL_SPLAY_LINKS *LeftChild;
    struct _RTL_SPLAY_LINKS *RightChild;
} RTL_SPLAY_LINKS, *PRTL_SPLAY_LINKS;

typedef struct _RTL_BALANCED_LINKS {
    struct _RTL_BALANCED_LINKS *Parent;
    struct _RTL_BALANCED_LINKS *LeftChild;
    struct _RTL_BALANCED_LINKS *RightChild;
    CHAR Balance;
    UCHAR Reserved[3];
} RTL_BALANCED_LINKS, *PRTL_BALANCED_LINKS;

typedef enum _TABLE_SEARCH_RESULT {
    TableEmptyTree,
    TableFoundNode,
    TableInsertAsLeft,
    TableInsertAsRight
} TABLE_SEARCH_RESULT;

typedef enum _RTL_GENERIC_COMPARE_RESULTS {
    GenericLessThan,
    GenericGreaterThan,
    GenericEqual
} RTL_GENERIC_COMPARE_RESULTS;

struct _RTL_AVL_TABLE;
typedef RTL_GENERIC_COMPARE_RESULTS RTL_AVL_COMPARE_ROUTINE(IN struct _RTL_AVL_TABLE *Table,
							    IN PVOID FirstStruct,
							    IN PVOID SecondStruct);
typedef RTL_AVL_COMPARE_ROUTINE *PRTL_AVL_COMPARE_ROUTINE;

typedef PVOID RTL_AVL_ALLOCATE_ROUTINE(IN struct _RTL_AVL_TABLE *Table,
				       IN CLONG ByteSize);
typedef RTL_AVL_ALLOCATE_ROUTINE *PRTL_AVL_ALLOCATE_ROUTINE;

typedef VOID RTL_AVL_FREE_ROUTINE(IN struct _RTL_AVL_TABLE *Table,
				  IN PVOID Buffer);
typedef RTL_AVL_FREE_ROUTINE *PRTL_AVL_FREE_ROUTINE;

typedef NTSTATUS RTL_AVL_MATCH_FUNCTION(IN struct _RTL_AVL_TABLE *Table,
					IN PVOID UserData,
					IN PVOID MatchData);
typedef RTL_AVL_MATCH_FUNCTION *PRTL_AVL_MATCH_FUNCTION;

typedef struct _RTL_AVL_TABLE {
    RTL_BALANCED_LINKS BalancedRoot;
    PVOID OrderedPointer;
    ULONG WhichOrderedElement;
    ULONG NumberGenericTableElements;
    ULONG DepthOfTree;
    PRTL_BALANCED_LINKS RestartKey;
    ULONG DeleteCount;
    PRTL_AVL_COMPARE_ROUTINE CompareRoutine;
    PRTL_AVL_ALLOCATE_ROUTINE AllocateRoutine;
    PRTL_AVL_FREE_ROUTINE FreeRoutine;
    PVOID TableContext;
} RTL_AVL_TABLE, *PRTL_AVL_TABLE;

/*
 * RTL Critical Section Structures
 */
typedef struct _RTL_CRITICAL_SECTION_DEBUG {
    USHORT Type;
    USHORT CreatorBackTraceIndex;
    struct _RTL_CRITICAL_SECTION *CriticalSection;
    LIST_ENTRY ProcessLocksList;
    ULONG EntryCount;
    ULONG ContentionCount;
    ULONG Flags;
    USHORT CreatorBackTraceIndexHigh;
    USHORT SpareWORD;
} RTL_CRITICAL_SECTION_DEBUG, *PRTL_CRITICAL_SECTION_DEBUG, RTL_RESOURCE_DEBUG, *PRTL_RESOURCE_DEBUG;

typedef struct _RTL_CRITICAL_SECTION {
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    ULONG_PTR SpinCount;
} RTL_CRITICAL_SECTION, *PRTL_CRITICAL_SECTION;

/*
 * RTL Resource
 */
#define RTL_RESOURCE_FLAG_LONG_TERM ((ULONG)0x00000001)

typedef struct _RTL_RESOURCE {
    RTL_CRITICAL_SECTION Lock;
    HANDLE SharedSemaphore;
    ULONG SharedWaiters;
    HANDLE ExclusiveSemaphore;
    ULONG ExclusiveWaiters;
    LONG NumberActive;
    HANDLE OwningThread;
    ULONG TimeoutBoost;
    PVOID DebugInfo;
} RTL_RESOURCE, *PRTL_RESOURCE;

/*
 * RTL Lock Type (Critical Section or Resource)
 */
#define RTL_CRITSECT_TYPE	0
#define RTL_RESOURCE_TYPE	1

/*
 * Trace Database
 */

typedef ULONG (NTAPI *RTL_TRACE_HASH_FUNCTION)(ULONG Count, PVOID *Trace);

typedef struct _RTL_TRACE_BLOCK {
    ULONG Magic;
    ULONG Count;
    ULONG Size;
    ULONG UserCount;
    ULONG UserSize;
    PVOID UserContext;
    struct _RTL_TRACE_BLOCK *Next;
    PVOID *Trace;
} RTL_TRACE_BLOCK, *PRTL_TRACE_BLOCK;

typedef struct _RTL_TRACE_DATABASE {
    ULONG Magic;
    ULONG Flags;
    ULONG Tag;
    struct _RTL_TRACE_SEGMENT *SegmentList;
    SIZE_T MaximumSize;
    SIZE_T CurrentSize;
    PVOID Owner;
    RTL_CRITICAL_SECTION Lock;
    ULONG NoOfBuckets;
    struct _RTL_TRACE_BLOCK **Buckets;
    RTL_TRACE_HASH_FUNCTION HashFunction;
    SIZE_T NoOfTraces;
    SIZE_T NoOfHits;
    ULONG HashCounter[16];
} RTL_TRACE_DATABASE, *PRTL_TRACE_DATABASE;

typedef struct _RTL_TRACE_SEGMENT {
    ULONG Magic;
    struct _RTL_TRACE_DATABASE *Database;
    struct _RTL_TRACE_SEGMENT *NextSegment;
    SIZE_T TotalSize;
    PCHAR SegmentStart;
    PCHAR SegmentEnd;
    PCHAR SegmentFree;
} RTL_TRACE_SEGMENT, *PRTL_TRACE_SEGMENT;

typedef struct _RTL_TRACE_ENUMERATE {
    struct _RTL_TRACE_DATABASE *Database;
    ULONG Index;
    struct _RTL_TRACE_BLOCK *Block;
} RTL_TRACE_ENUMERATE, *PRTL_TRACE_ENUMERATE;

/*
 * Bitmaps run
 */
typedef struct _RTL_BITMAP_RUN {
    ULONG StartingIndex;
    ULONG NumberOfBits;
} RTL_BITMAP_RUN, *PRTL_BITMAP_RUN;

#define MAXIMUM_LEADBYTES 12

/*
 * Code page info
 *
 * Some documentation can be found here: http://www.ping.uio.no/~ovehk/nls/
 */
typedef struct _CPTABLEINFO {
    USHORT CodePage;
    USHORT MaximumCharacterSize;       /* 1 = SBCS, 2 = DBCS */
    USHORT DefaultChar;                /* Default MultiByte Character for the CP->Unicode conversion */
    USHORT UniDefaultChar;             /* Default Unicode Character for the CP->Unicode conversion */
    USHORT TransDefaultChar;           /* Default MultiByte Character for the Unicode->CP conversion */
    USHORT TransUniDefaultChar;        /* Default Unicode Character for the Unicode->CP conversion */
    USHORT DBCSCodePage;
    UCHAR LeadByte[MAXIMUM_LEADBYTES];
    PUSHORT MultiByteTable;             /* Table for CP->Unicode conversion */
    PVOID WideCharTable;                /* Table for Unicode->CP conversion */
    PUSHORT DBCSRanges;
    PUSHORT DBCSOffsets;
} CPTABLEINFO, *PCPTABLEINFO;

/*
 * NLS table info
 */
typedef struct _NLSTABLEINFO {
    CPTABLEINFO OemTableInfo;
    CPTABLEINFO AnsiTableInfo;
    PUSHORT UpperCaseTable;
    PUSHORT LowerCaseTable;
} NLSTABLEINFO, *PNLSTABLEINFO;

/*
 * Header for NLS Files
 */
typedef struct _NLS_FILE_HEADER {
    USHORT HeaderSize;
    USHORT CodePage;
    USHORT MaximumCharacterSize;
    USHORT DefaultChar;
    USHORT UniDefaultChar;
    USHORT TransDefaultChar;
    USHORT TransUniDefaultChar;
    UCHAR LeadByte[MAXIMUM_LEADBYTES];
} NLS_FILE_HEADER, *PNLS_FILE_HEADER;

/*
 * Constant String Macro
 */
#define RTL_CONSTANT_STRING(__SOURCE_STRING__) {		\
    sizeof(__SOURCE_STRING__) - sizeof((__SOURCE_STRING__)[0]),	\
    sizeof(__SOURCE_STRING__), (__SOURCE_STRING__) }

/*
 * PE image routines
 */
NTAPI NTSYSAPI NTSTATUS RtlImageNtHeaderEx(IN ULONG Flags,
					   IN PVOID Base,
					   IN ULONG64 Size,
					   OUT PIMAGE_NT_HEADERS * OutHeaders);

NTAPI NTSYSAPI PIMAGE_NT_HEADERS RtlImageNtHeader(IN PVOID Base);

NTAPI NTSYSAPI PVOID RtlImageDirectoryEntryToData(IN PVOID BaseOfImage,
						  IN BOOLEAN MappedAsImage,
						  IN USHORT DirectoryEntry,
						  IN PULONG Size);

NTAPI NTSYSAPI PIMAGE_SECTION_HEADER RtlImageRvaToSection(IN PIMAGE_NT_HEADERS NtHeader,
							  IN PVOID BaseAddress,
							  IN ULONG Rva);

NTAPI NTSYSAPI PVOID RtlImageRvaToVa(IN PIMAGE_NT_HEADERS NtHeader,
				     IN PVOID BaseAddress,
				     IN ULONG Rva,
				     IN PIMAGE_SECTION_HEADER *SectionHeader);

/*
 * Unicode string functions
 */
NTAPI NTSYSAPI VOID RtlInitUnicodeString(IN OUT PUNICODE_STRING DestinationString,
					 IN PCWSTR SourceString);

NTAPI NTSYSAPI NTSTATUS RtlInitUnicodeStringEx(OUT PUNICODE_STRING DestinationString,
					       IN PCWSTR SourceString);

NTAPI NTSYSAPI LONG RtlCompareUnicodeString(IN PCUNICODE_STRING String1,
					    IN PCUNICODE_STRING String2,
					    IN BOOLEAN CaseInSensitive);

VOID NTAPI RtlFreeUnicodeString(IN PUNICODE_STRING UnicodeString);

NTAPI NTSYSAPI  BOOLEAN RtlEqualUnicodeString(IN PCUNICODE_STRING s1,
					      IN PCUNICODE_STRING s2,
					      IN BOOLEAN CaseInsensitive);

NTAPI NTSYSAPI NTSTATUS RtlUTF8ToUnicodeN(WCHAR *uni_dest, ULONG uni_bytes_max,
					  ULONG *uni_bytes_written,
					  const CHAR *utf8_src, ULONG utf8_bytes);

/*
 * Ansi string functions
 */
NTAPI NTSYSAPI VOID RtlInitAnsiString(OUT PANSI_STRING DestinationString,
				      IN OPTIONAL PCSZ SourceString);

NTAPI NTSYSAPI NTSTATUS RtlInitAnsiStringEx(OUT PANSI_STRING DestinationString,
					    IN OPTIONAL PCSZ SourceString);

/*
 * Single character functions
 */
NTAPI NTSYSAPI NTSTATUS RtlCharToInteger(IN PCSZ String,
					 IN ULONG Base,
					 OUT PULONG Value);

/*
 * NLS Functions
 */
NTAPI NTSYSAPI VOID RtlGetDefaultCodePage(OUT PUSHORT AnsiCodePage,
					  OUT PUSHORT OemCodePage);

NTAPI NTSYSAPI VOID RtlInitNlsTables(IN PUSHORT AnsiTableBase,
				     IN PUSHORT OemTableBase,
				     IN PUSHORT CaseTableBase,
				     OUT PNLSTABLEINFO NlsTable);

NTAPI NTSYSAPI VOID RtlInitCodePageTable(IN PUSHORT TableBase,
					 OUT PCPTABLEINFO CodePageTable);

NTAPI NTSYSAPI VOID RtlResetRtlTranslations(IN PNLSTABLEINFO NlsTable);

/*
 * Structured exception handling routines
 */
NTAPI NTSYSAPI NTSTATUS NtRaiseException(IN PEXCEPTION_RECORD ExceptionRecord,
					 IN PCONTEXT Context,
					 IN BOOLEAN SearchFrames);

NTAPI NTSYSAPI VOID RtlUnwind(IN PVOID TargetFrame OPTIONAL,
			      IN PVOID TargetIp OPTIONAL,
			      IN PEXCEPTION_RECORD ExceptionRecord OPTIONAL,
			      IN PVOID ReturnValue);

#ifdef _M_AMD64
NTAPI NTSYSAPI VOID RtlUnwindEx(IN PVOID TargetFrame OPTIONAL,
				IN PVOID TargetIp OPTIONAL,
				IN PEXCEPTION_RECORD ExceptionRecord OPTIONAL,
				IN PVOID ReturnValue,
				IN PCONTEXT ContextRecord,
				IN PUNWIND_HISTORY_TABLE HistoryTable OPTIONAL);
#endif

NTAPI NTSYSAPI PVOID RtlPcToFileHeader(IN PVOID PcValue,
				       OUT PVOID* BaseOfImage);

NTAPI NTSYSAPI VOID RtlCaptureContext(OUT PCONTEXT ContextRecord);

NTSYSAPI VOID RtlRestoreContext(PCONTEXT ContextRecord,
				PEXCEPTION_RECORD ExceptionRecord);

NTAPI NTSYSAPI BOOLEAN RtlDispatchException(IN PEXCEPTION_RECORD ExceptionRecord,
					    IN PCONTEXT Context);

NTAPI NTSYSAPI VOID RtlRaiseException(IN PEXCEPTION_RECORD ExceptionRecord);

NTAPI NTSYSAPI DECLSPEC_NORETURN VOID RtlRaiseStatus(IN NTSTATUS Status);

NTAPI NTSYSAPI USHORT RtlCaptureStackBackTrace(IN ULONG FramesToSkip,
					       IN ULONG FramesToCapture,
					       OUT PVOID *BackTrace,
					       OUT OPTIONAL PULONG BackTraceHash);

NTAPI NTSYSAPI VOID RtlSetUnhandledExceptionFilter(IN PRTLP_UNHANDLED_EXCEPTION_FILTER TopLevelExceptionFilter);

/*
 * Tracing Functions
 */
NTAPI NTSYSAPI ULONG RtlWalkFrameChain(OUT PVOID *Callers,
				       IN ULONG Count,
				       IN ULONG Flags);

NTAPI NTSYSAPI USHORT RtlLogStackBackTrace(VOID);

/*
 * Critical Section/Resource Functions
 */
NTAPI NTSYSAPI NTSTATUS RtlDeleteCriticalSection(IN PRTL_CRITICAL_SECTION CriticalSection);

NTAPI NTSYSAPI NTSTATUS RtlEnterCriticalSection(IN PRTL_CRITICAL_SECTION CriticalSection);

NTAPI NTSYSAPI NTSTATUS RtlInitializeCriticalSection(IN PRTL_CRITICAL_SECTION CriticalSection);

NTAPI NTSYSAPI NTSTATUS RtlInitializeCriticalSectionAndSpinCount(IN PRTL_CRITICAL_SECTION CriticalSection,
								 IN ULONG SpinCount);

NTAPI NTSYSAPI ULONG RtlIsCriticalSectionLocked(IN PRTL_CRITICAL_SECTION CriticalSection);

NTAPI NTSYSAPI ULONG RtlIsCriticalSectionLockedByThread(IN PRTL_CRITICAL_SECTION CriticalSection);

NTAPI NTSYSAPI NTSTATUS RtlLeaveCriticalSection(IN PRTL_CRITICAL_SECTION CriticalSection);

NTAPI NTSYSAPI BOOLEAN RtlTryEnterCriticalSection(IN PRTL_CRITICAL_SECTION CriticalSection);

NTAPI NTSYSAPI VOID RtlpUnWaitCriticalSection(IN PRTL_CRITICAL_SECTION CriticalSection);

NTAPI NTSYSAPI NTSTATUS RtlpWaitForCriticalSection(IN PRTL_CRITICAL_SECTION CriticalSection);

NTAPI NTSYSAPI BOOLEAN RtlAcquireResourceExclusive(IN PRTL_RESOURCE Resource,
						   IN BOOLEAN Wait);

NTAPI NTSYSAPI BOOLEAN RtlAcquireResourceShared(IN PRTL_RESOURCE Resource,
						IN BOOLEAN Wait);

NTAPI NTSYSAPI VOID RtlConvertExclusiveToShared(IN PRTL_RESOURCE Resource);

NTAPI NTSYSAPI VOID RtlConvertSharedToExclusive(IN PRTL_RESOURCE Resource);

NTAPI NTSYSAPI VOID RtlDeleteResource(IN PRTL_RESOURCE Resource);

NTAPI NTSYSAPI VOID RtlDumpResource(IN PRTL_RESOURCE Resource);

NTAPI NTSYSAPI VOID RtlInitializeResource(IN PRTL_RESOURCE Resource);

NTAPI NTSYSAPI VOID RtlReleaseResource(IN PRTL_RESOURCE Resource);

/*
 * Memory functions
 */

/*
 * VOID RtlCopyMemory(IN VOID UNALIGNED *Destination,
 *                    IN CONST VOID UNALIGNED *Source,
 *                    IN SIZE_T Length);
 */
#define RtlCopyMemory(Destination, Source, Length)	\
    memcpy(Destination, Source, Length)

NTAPI NTSYSAPI SIZE_T RtlCompareMemory(IN const VOID *Source1,
				       IN const VOID *Source2,
				       IN SIZE_T Length);

NTAPI NTSYSAPI SIZE_T RtlCompareMemoryUlong(IN PVOID Source,
					    IN SIZE_T Length,
					    IN ULONG Value);

/*
 * VOID RtlFillMemory(IN VOID UNALIGNED *Destination,
 *                    IN SIZE_T Length,
 *                    IN UCHAR Fill);
 */
#define RtlFillMemory(Destination, Length, Fill)	\
    memset(Destination, Fill, Length)

#ifdef _M_AMD64
FORCEINLINE VOID RtlFillMemoryUlong(OUT PVOID Destination,
				    IN SIZE_T Length,
				    IN ULONG Pattern)
{
    PULONG Address = (PULONG)Destination;
    if ((Length /= 4) != 0) {
	if (((ULONG64)Address & 4) != 0) {
	    *Address = Pattern;
	    if ((Length -= 1) == 0) {
		return;
	    }
	    Address += 1;
	}
	__stosq((PULONG64)(Address), Pattern | ((ULONG64)Pattern << 32), Length / 2);
	if ((Length & 1) != 0) Address[Length - 1] = Pattern;
    }
}

#define RtlFillMemoryUlonglong(Destination, Length, Pattern)	\
    __stosq((PULONG64)(Destination), Pattern, (Length) / 8)

#else
NTAPI NTSYSAPI VOID RtlFillMemoryUlong(PVOID Destination,
				       SIZE_T Length,
				       ULONG Fill);
#ifdef _WIN64
NTAPI NTSYSAPI VOID RtlFillMemoryUlonglong(PVOID Destination,
					   SIZE_T Length,
					   ULONGLONG Fill);
#endif // _WIN64
#endif // _M_AMD64

/*
 * VOID RtlMoveMemory(IN VOID UNALIGNED *Destination,
 *                    IN CONST VOID UNALIGNED *Source,
 *                    IN SIZE_T Length);
 */
#define RtlMoveMemory(Destination, Source, Length)	\
    memmove(Destination, Source, Length)

/*
 * VOID RtlZeroMemory(IN VOID UNALIGNED *Destination,
 *                    IN SIZE_T Length)
 */
#define RtlZeroMemory(Destination, Length)	\
    memset(Destination, 0, Length)

/*
 * Bitmap routines
 */

NTAPI NTSYSAPI VOID RtlInitializeBitMap(OUT PRTL_BITMAP BitMapHeader,
					IN OPTIONAL PULONG BitMapBuffer,
					IN OPTIONAL ULONG SizeOfBitMap);

NTAPI NTSYSAPI BOOLEAN RtlAreBitsClear(IN PRTL_BITMAP BitMapHeader,
				       IN ULONG StartingIndex,
				       IN ULONG Length);

NTAPI NTSYSAPI BOOLEAN RtlAreBitsSet(IN PRTL_BITMAP BitMapHeader,
				     IN ULONG StartingIndex,
				     IN ULONG Length);

NTAPI NTSYSAPI VOID RtlClearAllBits(IN PRTL_BITMAP BitMapHeader);

NTAPI NTSYSAPI VOID RtlClearBits(IN PRTL_BITMAP BitMapHeader,
				 IN ULONG StartingIndex,
				 IN ULONG NumberToClear);

NTAPI NTSYSAPI ULONG RtlFindClearBits(IN PRTL_BITMAP BitMapHeader,
				      IN ULONG NumberToFind,
				      IN ULONG HintIndex);

NTAPI NTSYSAPI ULONG RtlFindClearBitsAndSet(IN PRTL_BITMAP BitMapHeader,
					    IN ULONG NumberToFind,
					    IN ULONG HintIndex);

NTAPI NTSYSAPI ULONG RtlFindFirstRunClear(IN PRTL_BITMAP BitMapHeader,
					  OUT PULONG StartingIndex);

NTAPI NTSYSAPI ULONG RtlFindClearRuns(IN PRTL_BITMAP BitMapHeader,
				      OUT PRTL_BITMAP_RUN RunArray,
				      IN ULONG SizeOfRunArray,
				      IN BOOLEAN LocateLongestRuns);

NTAPI NTSYSAPI ULONG RtlFindLastBackwardRunClear(IN PRTL_BITMAP BitMapHeader,
						 IN ULONG FromIndex,
						 OUT PULONG StartingRunIndex);

NTAPI NTSYSAPI CCHAR RtlFindLeastSignificantBit(IN ULONGLONG Set);

NTAPI NTSYSAPI ULONG RtlFindLongestRunClear(IN PRTL_BITMAP BitMapHeader,
					    OUT PULONG StartingIndex);

NTAPI NTSYSAPI CCHAR RtlFindMostSignificantBit(IN ULONGLONG Set);

NTAPI NTSYSAPI ULONG RtlFindNextForwardRunClear(IN PRTL_BITMAP BitMapHeader,
						IN ULONG FromIndex,
						OUT PULONG StartingRunIndex);

NTAPI NTSYSAPI ULONG RtlFindSetBits(IN PRTL_BITMAP BitMapHeader,
				    IN ULONG NumberToFind,
				    IN ULONG HintIndex);

NTAPI NTSYSAPI ULONG RtlFindSetBitsAndClear(IN PRTL_BITMAP BitMapHeader,
					    IN ULONG NumberToFind,
					    IN ULONG HintIndex);

NTAPI NTSYSAPI ULONG RtlNumberOfClearBits(IN PRTL_BITMAP BitMapHeader);

NTAPI NTSYSAPI ULONG RtlNumberOfSetBits(IN PRTL_BITMAP BitMapHeader);

NTAPI NTSYSAPI VOID RtlSetAllBits(IN PRTL_BITMAP BitMapHeader);

NTAPI NTSYSAPI VOID RtlSetBits(IN PRTL_BITMAP BitMapHeader,
			       IN ULONG StartingIndex,
			       IN ULONG NumberToSet);

NTAPI NTSYSAPI VOID RtlClearBit(IN PRTL_BITMAP BitMapHeader,
				IN ULONG BitNumber);

NTAPI NTSYSAPI VOID RtlSetBit(IN PRTL_BITMAP BitMapHeader,
			      IN ULONG BitNumber);

NTAPI NTSYSAPI BOOLEAN RtlTestBit(IN PRTL_BITMAP BitMapHeader,
				  IN ULONG BitNumber);

#ifdef _M_AMD64
FORCEINLINE BOOLEAN RtlCheckBit(IN PRTL_BITMAP BitMapHeader,
				IN ULONG BitPosition)
{
    return BitTest64((LONG64 CONST*)BitMapHeader->Buffer, (LONG64)BitPosition);
}
#else
#define RtlCheckBit(BMH,BP) (((((PLONG)(BMH)->Buffer)[(BP)/32]) >> ((BP)%32)) & 0x1)
#endif /* _M_AMD64 */

/*
 * Debug functions
 */
NTAPI NTSYSAPI VOID DbgBreakPoint(VOID);
VOID DbgPrint(IN PCSTR Format, ...) __attribute__ ((format(printf, 1, 2)));

/*
 * Heap Functions
 */
NTAPI NTSYSAPI PVOID RtlAllocateHeap(IN PVOID HeapHandle,
				     IN OPTIONAL ULONG Flags,
				     IN SIZE_T Size);

NTAPI NTSYSAPI PVOID RtlCreateHeap(IN ULONG Flags,
				   IN OPTIONAL PVOID BaseAddress,
				   IN OPTIONAL SIZE_T SizeToReserve,
				   IN OPTIONAL SIZE_T SizeToCommit,
				   IN OPTIONAL PVOID Lock,
				   IN OPTIONAL PRTL_HEAP_PARAMETERS Parameters);

NTAPI NTSYSAPI ULONG RtlCreateTagHeap(IN HANDLE HeapHandle,
				      IN ULONG Flags,
				      IN PWSTR TagName,
				      IN PWSTR TagSubName);

NTAPI NTSYSAPI ULONG RtlCompactHeap(IN HANDLE Heap,
				    IN ULONG Flags);

NTAPI NTSYSAPI HANDLE RtlDestroyHeap(IN HANDLE Heap);

NTAPI NTSYSAPI ULONG RtlExtendHeap(IN HANDLE Heap,
				   IN ULONG Flags,
				   IN PVOID P,
				   IN SIZE_T Size);

NTAPI NTSYSAPI BOOLEAN RtlFreeHeap(IN HANDLE HeapHandle,
				   IN OPTIONAL ULONG Flags,
				   IN PVOID P);

NTAPI NTSYSAPI ULONG RtlGetProcessHeaps(IN ULONG HeapCount,
					OUT HANDLE *HeapArray);

NTAPI NTSYSAPI BOOLEAN RtlGetUserInfoHeap(IN PVOID HeapHandle,
					  IN ULONG Flags,
					  IN PVOID BaseAddress,
					  IN OUT OPTIONAL PVOID *UserValue,
					  OUT OPTIONAL PULONG UserFlags);

NTAPI NTSYSAPI PVOID RtlProtectHeap(IN PVOID HeapHandle,
				    IN BOOLEAN Protect);

NTAPI NTSYSAPI NTSTATUS RtlQueryHeapInformation(IN PVOID HeapHandle,
						IN HEAP_INFORMATION_CLASS HeapInformationClass,
						OUT PVOID HeapInformation,
						IN SIZE_T HeapInformationLength,
						OUT OPTIONAL PSIZE_T ReturnLength);

NTAPI NTSYSAPI PWSTR RtlQueryTagHeap(IN PVOID HeapHandle,
				     IN ULONG Flags,
				     IN USHORT TagIndex,
				     IN BOOLEAN ResetCounters,
				     OUT PRTL_HEAP_TAG_INFO HeapTagInfo);

NTAPI NTSYSAPI PVOID RtlReAllocateHeap(IN HANDLE Heap,
				       IN OPTIONAL ULONG Flags,
				       IN PVOID Ptr,
				       IN SIZE_T Size);

NTAPI NTSYSAPI NTSTATUS RtlSetHeapInformation(IN PVOID HeapHandle,
					      IN HEAP_INFORMATION_CLASS HeapInformationClass,
					      IN PVOID HeapInformation,
					      IN SIZE_T HeapInformationLength);

NTAPI NTSYSAPI BOOLEAN RtlLockHeap(IN HANDLE Heap);

NTAPI NTSYSAPI ULONG RtlMultipleAllocateHeap(IN HANDLE HeapHandle,
					     IN ULONG Flags,
					     IN SIZE_T Size,
					     IN ULONG Count,
					     OUT PVOID *Array);

NTAPI NTSYSAPI ULONG RtlMultipleFreeHeap(IN HANDLE HeapHandle,
					 IN ULONG Flags,
					 IN ULONG Count,
					 IN PVOID *Array);

NTAPI NTSYSAPI NTSTATUS RtlUsageHeap(IN HANDLE Heap,
				     IN ULONG Flags,
				     OUT PRTL_HEAP_USAGE Usage);

NTAPI NTSYSAPI BOOLEAN RtlUnlockHeap(IN HANDLE Heap);

NTAPI NTSYSAPI BOOLEAN RtlSetUserValueHeap(IN PVOID HeapHandle,
					   IN ULONG Flags,
					   IN PVOID BaseAddress,
					   IN PVOID UserValue);

NTAPI NTSYSAPI BOOLEAN RtlSetUserFlagsHeap(IN PVOID HeapHandle,
					   IN ULONG Flags,
					   IN PVOID BaseAddress,
					   IN ULONG UserFlagsReset,
					   IN ULONG UserFlagsSet);

NTAPI NTSYSAPI BOOLEAN RtlValidateHeap(IN HANDLE Heap,
				       IN ULONG Flags,
				       IN OPTIONAL PVOID P);

NTAPI NTSYSAPI NTSTATUS RtlWalkHeap(IN HANDLE HeapHandle,
				    IN PVOID HeapEntry);

#define RtlGetProcessHeap() (NtCurrentPeb()->ProcessHeap)

NTAPI NTSYSAPI SIZE_T RtlSizeHeap(IN PVOID HeapHandle,
				  IN ULONG Flags,
				  IN PVOID MemoryPointer);

/*
 * RTL Splay Tree Functions
 */
NTAPI NTSYSAPI PRTL_SPLAY_LINKS RtlSplay(IN OUT PRTL_SPLAY_LINKS Links);

NTAPI NTSYSAPI PRTL_SPLAY_LINKS RtlDelete(IN PRTL_SPLAY_LINKS Links);

NTAPI NTSYSAPI VOID RtlDeleteNoSplay(IN PRTL_SPLAY_LINKS Links,
				     IN OUT PRTL_SPLAY_LINKS *Root);

NTAPI NTSYSAPI PRTL_SPLAY_LINKS RtlSubtreeSuccessor(IN PRTL_SPLAY_LINKS Links);

NTAPI NTSYSAPI PRTL_SPLAY_LINKS RtlSubtreePredecessor(IN PRTL_SPLAY_LINKS Links);

NTAPI NTSYSAPI PRTL_SPLAY_LINKS RtlRealSuccessor(IN PRTL_SPLAY_LINKS Links);

NTAPI NTSYSAPI PRTL_SPLAY_LINKS RtlRealPredecessor(IN PRTL_SPLAY_LINKS Links);

#define RtlIsLeftChild(Links)						\
    (RtlLeftChild(RtlParent(Links)) == (PRTL_SPLAY_LINKS)(Links))

#define RtlIsRightChild(Links)						\
    (RtlRightChild(RtlParent(Links)) == (PRTL_SPLAY_LINKS)(Links))

#define RtlRightChild(Links)			\
    ((PRTL_SPLAY_LINKS)(Links))->RightChild

#define RtlIsRoot(Links)				\
    (RtlParent(Links) == (PRTL_SPLAY_LINKS)(Links))

#define RtlLeftChild(Links)			\
    ((PRTL_SPLAY_LINKS)(Links))->LeftChild

#define RtlParent(Links)			\
    ((PRTL_SPLAY_LINKS)(Links))->Parent

// FIXME: use inline function

#define RtlInitializeSplayLinks(Links)                  \
    {                                                   \
        PRTL_SPLAY_LINKS _SplayLinks;                   \
        _SplayLinks = (PRTL_SPLAY_LINKS)(Links);        \
        _SplayLinks->Parent = _SplayLinks;              \
        _SplayLinks->LeftChild = NULL;                  \
        _SplayLinks->RightChild = NULL;                 \
    }

#define RtlInsertAsLeftChild(ParentLinks,ChildLinks)    \
    {                                                   \
        PRTL_SPLAY_LINKS _SplayParent;                  \
        PRTL_SPLAY_LINKS _SplayChild;                   \
        _SplayParent = (PRTL_SPLAY_LINKS)(ParentLinks); \
        _SplayChild = (PRTL_SPLAY_LINKS)(ChildLinks);   \
        _SplayParent->LeftChild = _SplayChild;          \
        _SplayChild->Parent = _SplayParent;             \
    }

#define RtlInsertAsRightChild(ParentLinks,ChildLinks)   \
    {                                                   \
        PRTL_SPLAY_LINKS _SplayParent;                  \
        PRTL_SPLAY_LINKS _SplayChild;                   \
        _SplayParent = (PRTL_SPLAY_LINKS)(ParentLinks); \
        _SplayChild = (PRTL_SPLAY_LINKS)(ChildLinks);   \
        _SplayParent->RightChild = _SplayChild;         \
        _SplayChild->Parent = _SplayParent;             \
    }

/*
 * RTL AVL Tree Functions
 */
NTAPI NTSYSAPI VOID RtlInitializeGenericTableAvl(OUT PRTL_AVL_TABLE Table,
						 IN PRTL_AVL_COMPARE_ROUTINE CompareRoutine,
						 IN OPTIONAL PRTL_AVL_ALLOCATE_ROUTINE AllocateRoutine,
						 IN OPTIONAL PRTL_AVL_FREE_ROUTINE FreeRoutine,
						 IN OPTIONAL PVOID TableContext);

NTAPI NTSYSAPI PVOID RtlInsertElementGenericTableAvl(IN PRTL_AVL_TABLE Table,
						     IN PVOID Buffer,
						     IN CLONG BufferSize,
						     OUT OPTIONAL PBOOLEAN NewElement);

NTAPI NTSYSAPI PVOID RtlInsertElementGenericTableFullAvl(IN PRTL_AVL_TABLE Table,
							 IN PVOID Buffer,
							 IN CLONG BufferSize,
							 OUT OPTIONAL PBOOLEAN NewElement,
							 IN PVOID NodeOrParent,
							 IN TABLE_SEARCH_RESULT SearchResult);

NTAPI NTSYSAPI BOOLEAN RtlDeleteElementGenericTableAvl(IN PRTL_AVL_TABLE Table,
						       IN PVOID Buffer);

NTAPI NTSYSAPI PVOID RtlLookupElementGenericTableAvl(IN PRTL_AVL_TABLE Table,
						     IN PVOID Buffer);

NTAPI NTSYSAPI PVOID RtlLookupElementGenericTableFullAvl(IN PRTL_AVL_TABLE Table,
							 IN PVOID Buffer,
							 OUT PVOID *NodeOrParent,
							 OUT TABLE_SEARCH_RESULT *SearchResult);

NTAPI NTSYSAPI PVOID RtlEnumerateGenericTableAvl(IN PRTL_AVL_TABLE Table,
						 IN BOOLEAN Restart);

NTAPI NTSYSAPI PVOID RtlEnumerateGenericTableWithoutSplayingAvl(IN PRTL_AVL_TABLE Table,
								IN OUT PVOID *RestartKey);

NTAPI NTSYSAPI PVOID RtlLookupFirstMatchingElementGenericTableAvl(IN PRTL_AVL_TABLE Table,
								  IN PVOID Buffer,
								  OUT PVOID *RestartKey);

NTAPI NTSYSAPI PVOID RtlEnumerateGenericTableLikeADirectory(IN PRTL_AVL_TABLE Table,
							    IN OPTIONAL PRTL_AVL_MATCH_FUNCTION MatchFunction,
							    IN OPTIONAL PVOID MatchData,
							    IN ULONG NextFlag,
							    IN OUT PVOID *RestartKey,
							    IN OUT PULONG DeleteCount,
							    IN PVOID Buffer);

NTAPI NTSYSAPI PVOID RtlGetElementGenericTableAvl(IN PRTL_AVL_TABLE Table,
						  IN ULONG I);

NTAPI NTSYSAPI ULONG RtlNumberGenericTableElementsAvl(IN PRTL_AVL_TABLE Table);

NTAPI NTSYSAPI BOOLEAN RtlIsGenericTableEmptyAvl(IN PRTL_AVL_TABLE Table);

/*
 * Configuration manager routines
 */
NTAPI NTSYSAPI ULONG RtlGetNtGlobalFlags(VOID);

/*
 * Error status routines
 */
NTAPI NTSYSAPI NTSTATUS RtlGetLastNtStatus(VOID);

NTAPI NTSYSAPI ULONG RtlGetLastWin32Error(VOID);

NTAPI NTSYSAPI VOID RtlSetLastWin32Error(IN ULONG LastError);

NTAPI NTSYSAPI VOID RtlSetLastWin32ErrorAndNtStatusFromNtStatus(IN NTSTATUS Status);

NTAPI NTSYSAPI NTSTATUS RtlSetThreadErrorMode(IN ULONG NewMode,
					      OUT OPTIONAL PULONG OldMode);

NTAPI NTSYSAPI ULONG RtlGetThreadErrorMode(VOID);

NTAPI NTSYSAPI PVOID RtlEncodePointer(IN PVOID Pointer);

NTAPI NTSYSAPI PVOID RtlDecodePointer(IN PVOID Pointer);

NTAPI NTSYSAPI PVOID RtlEncodeSystemPointer(IN PVOID Pointer);

NTAPI NTSYSAPI PVOID RtlDecodeSystemPointer(IN PVOID Pointer);

/*
 * Interlocked sequenced (singly-linked) list
 */
NTAPI NTSYSAPI VOID RtlInitializeSListHead(OUT PSLIST_HEADER ListHead);

NTAPI NTSYSAPI PSLIST_ENTRY RtlFirstEntrySList(IN const SLIST_HEADER *ListHead);

NTAPI NTSYSAPI PSLIST_ENTRY RtlInterlockedPopEntrySList(IN OUT PSLIST_HEADER ListHead);

NTAPI NTSYSAPI PSLIST_ENTRY RtlInterlockedPushEntrySList(IN OUT PSLIST_HEADER ListHead,
							 IN OUT PSLIST_ENTRY ListEntry);

NTAPI NTSYSAPI PSLIST_ENTRY RtlInterlockedFlushSList(IN OUT PSLIST_HEADER ListHead);

NTAPI NTSYSAPI USHORT RtlQueryDepthSList(IN PSLIST_HEADER ListHead);

/*
 * Process Management Functions
 */

#ifdef _M_IX86
#define __TLSBASE_READ	__readfsdword
#elif defined(_M_AMD64)
#define __TLSBASE_READ	__readgsqword
#else
#error "Unsupported architecture"
#endif

FORCEINLINE PTEB NtCurrentTeb(VOID)
{
    return (PTEB) __TLSBASE_READ(FIELD_OFFSET(NT_TIB, Self));
}

FORCEINLINE PPEB NtCurrentPeb(VOID)
{
    return NtCurrentTeb()->ProcessEnvironmentBlock;
}

#undef __TLSBASE_READ

#define RtlGetCurrentPeb NtCurrentPeb

/*
 * Process entry point for Native executables
 */
NTAPI NTSYSAPI VOID RtlAcquirePebLock(VOID);

NTAPI NTSYSAPI NTSTATUS
RtlCreateProcessParameters(OUT PRTL_USER_PROCESS_PARAMETERS *ProcessParameters,
			   IN PUNICODE_STRING ImagePathName,
			   IN OPTIONAL PUNICODE_STRING DllPath,
			   IN OPTIONAL PUNICODE_STRING CurrentDirectory,
			   IN OPTIONAL PUNICODE_STRING CommandLine,
			   IN OPTIONAL PWSTR Environment,
			   IN OPTIONAL PUNICODE_STRING WindowTitle,
			   IN OPTIONAL PUNICODE_STRING DesktopInfo,
			   IN OPTIONAL PUNICODE_STRING ShellInfo,
			   IN OPTIONAL PUNICODE_STRING RuntimeInfo);

NTAPI NTSYSAPI NTSTATUS
RtlCreateUserProcess(IN PUNICODE_STRING ImageFileName,
		     IN ULONG Attributes,
		     IN PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
		     IN OPTIONAL PSECURITY_DESCRIPTOR ProcessSecutityDescriptor,
		     IN OPTIONAL PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
		     IN OPTIONAL HANDLE ParentProcess,
		     IN BOOLEAN CurrentDirectory,
		     IN OPTIONAL HANDLE DebugPort,
		     IN OPTIONAL HANDLE ExceptionPort,
		     OUT PRTL_USER_PROCESS_INFORMATION ProcessInfo);

NTAPI NTSYSAPI NTSTATUS
RtlCreateUserThread(IN HANDLE ProcessHandle,
		    IN OPTIONAL PSECURITY_DESCRIPTOR SecurityDescriptor,
		    IN BOOLEAN CreateSuspended,
		    IN ULONG StackZeroBits,
		    IN SIZE_T StackReserve,
		    IN SIZE_T StackCommit,
		    IN PTHREAD_START_ROUTINE StartAddress,
		    IN PVOID Parameter,
		    OUT OPTIONAL PHANDLE ThreadHandle,
		    OUT OPTIONAL PCLIENT_ID ClientId);

NTAPI NTSYSAPI VOID RtlExitUserThread(IN NTSTATUS Status);

NTAPI NTSYSAPI VOID
RtlInitializeContext(IN HANDLE ProcessHandle,
		     OUT PCONTEXT ThreadContext,
		     IN OPTIONAL PVOID ThreadStartParam,
		     IN PTHREAD_START_ROUTINE ThreadStartAddress,
		     IN PINITIAL_TEB InitialTeb);

/*
 * Loader routines
 */
NTAPI NTSYSAPI NTSTATUS LdrShutdownProcess(VOID);

NTAPI NTSYSAPI NTSTATUS LdrShutdownThread(VOID);

NTAPI NTSYSAPI NTSTATUS LdrGetProcedureAddress(IN PVOID BaseAddress,
					       IN PANSI_STRING Name,
					       IN ULONG Ordinal,
					       OUT PVOID *ProcedureAddress);

NTAPI NTSYSAPI NTSTATUS LdrFindEntryForAddress(IN PVOID Address,
					       OUT PLDR_DATA_TABLE_ENTRY *Module);
