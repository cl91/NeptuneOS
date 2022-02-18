#pragma once

#include <ntimage.h>
#include <ntkeapi.h>

#define MAX_PATH	260

#define RTL_UNCHANGED_UNK_PATH  1
#define RTL_CONVERTED_UNC_PATH  2
#define RTL_CONVERTED_NT_PATH   3
#define RTL_UNCHANGED_DOS_PATH  4

#define RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK (0x00000001)

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

/*
 * Current Directory Structures
 */
typedef struct _CURDIR {
    UNICODE_STRING DosPath;
    PVOID Handle;
} CURDIR, *PCURDIR;

typedef struct _RTLP_CURDIR_REF {
    LONG RefCount;
    HANDLE Handle;
} RTLP_CURDIR_REF, *PRTLP_CURDIR_REF;

typedef struct _RTL_RELATIVE_NAME_U {
    UNICODE_STRING RelativeName;
    HANDLE ContainingDirectory;
    PRTLP_CURDIR_REF CurDirRef;
} RTL_RELATIVE_NAME_U, *PRTL_RELATIVE_NAME_U;

typedef struct RTL_DRIVE_LETTER_CURDIR {
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    UNICODE_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_PERTHREAD_CURDIR {
    PRTL_DRIVE_LETTER_CURDIR CurrentDirectories;
    PUNICODE_STRING ImageName;
    PVOID Environment;
} RTL_PERTHREAD_CURDIR, *PRTL_PERTHREAD_CURDIR;

/*
 * RTL Path Types
 */
typedef enum _RTL_PATH_TYPE {
    RtlPathTypeUnknown,
    RtlPathTypeUncAbsolute,
    RtlPathTypeDriveAbsolute,
    RtlPathTypeDriveRelative,
    RtlPathTypeRooted,
    RtlPathTypeRelative,
    RtlPathTypeLocalDevice,
    RtlPathTypeRootLocalDevice,
} RTL_PATH_TYPE;

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

#define RTL_MAX_DRIVE_LETTERS 32
#define RTL_DRIVE_LETTER_VALID (USHORT)0x0001

/*
 * Thread and Process Start Routines for RtlCreateUserThread/Process
 */
typedef ULONG (NTAPI *PTHREAD_START_ROUTINE)(PVOID Parameter);

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;
    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PWSTR Environment;
    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];
    SIZE_T EnvironmentSize;
    SIZE_T EnvironmentVersion;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME {
    struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME *Previous;
    struct _ACTIVATION_CONTEXT                 *ActivationContext;
    ULONG                                       Flags;
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, *PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

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

typedef struct _EXCEPTION_POINTERS {
  PEXCEPTION_RECORD ExceptionRecord;
  PCONTEXT ContextRecord;
} EXCEPTION_POINTERS, *PEXCEPTION_POINTERS;

/* Pseudo handle values for current process and thread */
static inline HANDLE NtCurrentProcess(VOID)
{
    return (HANDLE)((LONG_PTR)(-1));
}

static inline HANDLE NtCurrentThread(VOID)
{
    return ((HANDLE)(LONG_PTR)(-2));
}

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

#ifndef _NTOSKRNL_
#include <nturtl.h>
#endif	/* _NTOSKRNL_ */
