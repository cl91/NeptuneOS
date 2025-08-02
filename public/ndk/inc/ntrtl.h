#pragma once

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

#if defined(_MSC_VER) && !defined(_NTOSKRNL_)
#include <nturtl.h>
#endif
