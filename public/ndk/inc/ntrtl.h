#pragma once

#include <ntmmapi.h>
#include <ntimage.h>

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

/*
 * Time Structure for RTL Time calls
 */
typedef struct _TIME_FIELDS {
    CSHORT Year;
    CSHORT Month;
    CSHORT Day;
    CSHORT Hour;
    CSHORT Minute;
    CSHORT Second;
    CSHORT Milliseconds;
    CSHORT Weekday;
} TIME_FIELDS, *PTIME_FIELDS;

typedef struct _RTL_BITMAP {
    ULONG SizeOfBitMap;		/* Number of bits in the bitmap */
    PULONG Buffer; /* Bitmap data, assumed sized to a DWORD boundary */
} RTL_BITMAP, *PRTL_BITMAP;

typedef const RTL_BITMAP *PCRTL_BITMAP;

typedef struct _RTL_USER_PROCESS_INFORMATION {
    ULONG Size;
    HANDLE ProcessHandle;
    HANDLE ThreadHandle;
    CLIENT_ID ClientId;
    SECTION_IMAGE_INFORMATION ImageInformation;
} RTL_USER_PROCESS_INFORMATION, *PRTL_USER_PROCESS_INFORMATION;

/*
 * Information Structures for RTL Debug Functions
 */
typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    ULONG Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    CHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

/*
 * Thread Entrypoint
 */
typedef ULONG (NTAPI *PTHREAD_START_ROUTINE)(PVOID Parameter);

/* Exception record flags */
#define EXCEPTION_NONCONTINUABLE  0x01
#define EXCEPTION_UNWINDING       0x02
#define EXCEPTION_EXIT_UNWIND     0x04
#define EXCEPTION_STACK_INVALID   0x08
#define EXCEPTION_NESTED_CALL     0x10
#define EXCEPTION_TARGET_UNWIND   0x20
#define EXCEPTION_COLLIDED_UNWIND 0x40
#define EXCEPTION_UNWIND (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND | \
                          EXCEPTION_TARGET_UNWIND | EXCEPTION_COLLIDED_UNWIND)

#define IS_UNWINDING(Flag) ((Flag & EXCEPTION_UNWIND) != 0)
#define IS_DISPATCHING(Flag) ((Flag & EXCEPTION_UNWIND) == 0)
#define IS_TARGET_UNWIND(Flag) (Flag & EXCEPTION_TARGET_UNWIND)

#define EXCEPTION_MAXIMUM_PARAMETERS 15

/* Exception records */
typedef struct _EXCEPTION_RECORD {
    NTSTATUS ExceptionCode;
    ULONG ExceptionFlags;
    struct _EXCEPTION_RECORD *ExceptionRecord;
    PVOID ExceptionAddress;
    ULONG NumberParameters;
    ULONG_PTR ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD, *PEXCEPTION_RECORD;

/* Pseudo handle values for current process and thread */
static inline HANDLE NtCurrentProcess(VOID)
{
    return (HANDLE)((LONG_PTR)(-1));
}

static inline HANDLE NtCurrentThread(VOID)
{
    return ((HANDLE)(LONG_PTR)(-2));
}

/*
 * Unicode and UTF-8 Conversion Routines
 */
NTAPI NTSYSAPI NTSTATUS RtlUnicodeToUTF8N(CHAR *utf8_dest, ULONG utf8_bytes_max,
					  ULONG *utf8_bytes_written,
					  const WCHAR *uni_src, ULONG uni_bytes);

NTAPI NTSYSAPI NTSTATUS RtlUTF8ToUnicodeN(WCHAR *uni_dest, ULONG uni_bytes_max,
					  ULONG *uni_bytes_written,
					  const CHAR *utf8_src,
					  ULONG utf8_bytes);

NTAPI NTSYSAPI CCHAR RtlFindMostSignificantBit(IN ULONGLONG Set);

NTAPI NTSYSAPI CCHAR RtlFindLeastSignificantBit(IN ULONGLONG Set);

/*
 * Memory functions
 */

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
 * VOID RtlCopyMemory(IN VOID UNALIGNED *Destination,
 *                    IN CONST VOID UNALIGNED *Source,
 *                    IN SIZE_T Length);
 */
#define RtlCopyMemory(Destination, Source, Length)	\
    memcpy(Destination, Source, Length)

/*
 * BOOLEAN RtlEqualMemory(IN VOID UNALIGNED *Destination,
 *                        IN CONST VOID UNALIGNED *Source,
 *                        IN SIZE_T Length)
 */
#define RtlEqualMemory(Destination, Source, Length)	\
    (!memcmp(Destination, Source, Length))

/*
 * VOID RtlFillMemory(IN VOID UNALIGNED *Destination,
 *                    IN SIZE_T Length,
 *                    IN UCHAR Fill);
 */
#define RtlFillMemory(Destination, Length, Fill)	\
    memset(Destination, Fill, Length)

/*
 * Time Functions
 */
NTAPI NTSYSAPI BOOLEAN RtlCutoverTimeToSystemTime(IN PTIME_FIELDS CutoverTimeFields,
						  OUT PLARGE_INTEGER SystemTime,
						  IN PLARGE_INTEGER CurrentTime,
						  IN BOOLEAN ThisYearsCutoverOnly);

NTAPI NTSYSAPI VOID RtlTimeToElapsedTimeFields(IN PLARGE_INTEGER Time,
					       OUT PTIME_FIELDS TimeFields);

NTAPI NTSYSAPI BOOLEAN RtlTimeFieldsToTime(IN PTIME_FIELDS TimeFields,
					   OUT PLARGE_INTEGER Time);

NTAPI NTSYSAPI VOID RtlTimeToTimeFields(IN PLARGE_INTEGER Time,
					OUT PTIME_FIELDS TimeFields);

NTAPI NTSYSAPI VOID RtlSecondsSince1970ToTime(IN ULONG SecondsSince1970,
					      OUT PLARGE_INTEGER Time);

NTAPI NTSYSAPI BOOLEAN RtlTimeToSecondsSince1970(IN PLARGE_INTEGER Time,
						 OUT PULONG ElapsedSeconds);

NTAPI NTSYSAPI BOOLEAN RtlTimeToSecondsSince1980(IN PLARGE_INTEGER Time,
						 OUT PULONG ElapsedSeconds);

NTAPI NTSYSAPI VOID RtlSecondsSince1980ToTime(IN ULONG ElapsedSeconds,
					      OUT PLARGE_INTEGER Time);

NTAPI NTSYSAPI ULONG RtlComputeCrc32(IN ULONG InitialCrc,
				     IN const UCHAR *Data,
				     IN ULONG Length);

/*
 * Range and Range List Flags
 */
#define RTL_RANGE_LIST_ADD_IF_CONFLICT                      0x00000001
#define RTL_RANGE_LIST_ADD_SHARED                           0x00000002

#define RTL_RANGE_SHARED                                    0x01
#define RTL_RANGE_CONFLICT                                  0x02

/*
 * RTL Range List Structures
 */
typedef struct _RTL_RANGE_LIST {
    LIST_ENTRY ListHead;
    ULONG Flags;
    ULONG Count;
    ULONG Stamp;
} RTL_RANGE_LIST, *PRTL_RANGE_LIST;

typedef struct _RTL_RANGE {
    ULONGLONG Start;
    ULONGLONG End;
    PVOID UserData;
    PVOID Owner;
    UCHAR Attributes;
    UCHAR Flags;
} RTL_RANGE, *PRTL_RANGE;

typedef struct _RANGE_LIST_ITERATOR {
    PLIST_ENTRY RangeListHead;
    PLIST_ENTRY MergedHead;
    PVOID Current;
    ULONG Stamp;
} RTL_RANGE_LIST_ITERATOR, *PRTL_RANGE_LIST_ITERATOR;

typedef struct _RTLP_RANGE_LIST_ENTRY {
    ULONGLONG Start;
    ULONGLONG End;
    union {
        struct {
            PVOID UserData;
            PVOID Owner;
        } Allocated;
        struct {
            LIST_ENTRY ListHead;
        } Merged;
    };
    UCHAR Attributes;
    UCHAR PublicFlags;
    USHORT PrivateFlags;
    LIST_ENTRY ListEntry;
} RTLP_RANGE_LIST_ENTRY, *PRTLP_RANGE_LIST_ENTRY;

C_ASSERT(RTL_SIZEOF_THROUGH_FIELD(RTL_RANGE, Flags) ==
	 RTL_SIZEOF_THROUGH_FIELD(RTLP_RANGE_LIST_ENTRY, PublicFlags));

/*
 * RTL Range List callbacks
 */
typedef BOOLEAN (NTAPI *PRTL_CONFLICT_RANGE_CALLBACK)(PVOID Context,
						      PRTL_RANGE Range);

/*
 * Range List functions
 */
NTAPI NTSYSAPI VOID RtlInitializeRangeList(OUT PRTL_RANGE_LIST RangeList);

NTAPI NTSYSAPI VOID RtlFreeRangeList(IN PRTL_RANGE_LIST RangeList);

NTAPI NTSYSAPI NTSTATUS RtlCopyRangeList(OUT PRTL_RANGE_LIST CopyRangeList,
					 IN PRTL_RANGE_LIST RangeList);

NTAPI NTSYSAPI NTSTATUS RtlMergeRangeLists(OUT PRTL_RANGE_LIST MergedRangeList,
					   IN PRTL_RANGE_LIST RangeList1,
					   IN PRTL_RANGE_LIST RangeList2,
					   IN ULONG Flags);

NTAPI NTSYSAPI NTSTATUS RtlInvertRangeList(OUT PRTL_RANGE_LIST InvertedRangeList,
					   IN PRTL_RANGE_LIST RangeList);

NTAPI NTSYSAPI NTSTATUS RtlAddRange(IN OUT PRTL_RANGE_LIST RangeList,
				    IN ULONGLONG Start,
				    IN ULONGLONG End,
				    IN UCHAR Attributes,
				    IN ULONG Flags,
				    IN OPTIONAL PVOID UserData,
				    IN OPTIONAL PVOID Owner);

NTAPI NTSYSAPI NTSTATUS RtlDeleteRange(IN OUT PRTL_RANGE_LIST RangeList,
				       IN ULONGLONG Start,
				       IN ULONGLONG End,
				       IN PVOID Owner);

NTAPI NTSYSAPI NTSTATUS RtlDeleteOwnersRanges(IN OUT PRTL_RANGE_LIST RangeList,
					      IN PVOID Owner);

NTAPI NTSYSAPI NTSTATUS RtlFindRange(IN PRTL_RANGE_LIST RangeList,
				     IN ULONGLONG Minimum,
				     IN ULONGLONG Maximum,
				     IN ULONG Length,
				     IN ULONG Alignment,
				     IN ULONG Flags,
				     IN UCHAR AttributeAvailableMask,
				     IN OPTIONAL PVOID Context,
				     IN OPTIONAL PRTL_CONFLICT_RANGE_CALLBACK Callback,
				     OUT PULONGLONG Start);

NTAPI NTSYSAPI NTSTATUS RtlIsRangeAvailable(IN PRTL_RANGE_LIST RangeList,
					    IN ULONGLONG Start,
					    IN ULONGLONG End,
					    IN ULONG Flags,
					    IN UCHAR AttributeAvailableMask,
					    IN OPTIONAL PVOID Context,
					    IN OPTIONAL PRTL_CONFLICT_RANGE_CALLBACK Callback,
					    OUT PBOOLEAN Available);

NTAPI NTSYSAPI NTSTATUS RtlGetFirstRange(IN PRTL_RANGE_LIST RangeList,
					 OUT PRTL_RANGE_LIST_ITERATOR Iterator,
					 OUT PRTL_RANGE *Range);

NTAPI NTSYSAPI NTSTATUS RtlGetNextRange(IN OUT PRTL_RANGE_LIST_ITERATOR Iterator,
					OUT PRTL_RANGE *Range,
					IN BOOLEAN MoveForwards);

#if defined(_MSC_VER) && !defined(_NTOSKRNL_)
#include <nturtl.h>
#endif
