#pragma once

#include <ntimage.h>
#include <ntkeapi.h>

#define RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK (0x00000001)

NTSTATUS NTAPI RtlImageNtHeaderEx(IN ULONG Flags,
				  IN PVOID Base,
				  IN ULONG64 Size,
				  OUT PIMAGE_NT_HEADERS * OutHeaders);

PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(IN PVOID Base);

PVOID NTAPI RtlImageDirectoryEntryToData(IN PVOID BaseOfImage,
					 IN BOOLEAN MappedAsImage,
					 IN USHORT DirectoryEntry,
					 IN PULONG Size);

PIMAGE_SECTION_HEADER NTAPI RtlImageRvaToSection(IN PIMAGE_NT_HEADERS NtHeader,
						 IN PVOID BaseAddress,
						 IN ULONG Rva);

PVOID NTAPI RtlImageRvaToVa(IN PIMAGE_NT_HEADERS NtHeader,
			    IN PVOID BaseAddress,
			    IN ULONG Rva,
			    IN PIMAGE_SECTION_HEADER *SectionHeader);

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
    ULONG Spare[2];
} RTL_CRITICAL_SECTION_DEBUG, *PRTL_CRITICAL_SECTION_DEBUG, RTL_RESOURCE_DEBUG, *PRTL_RESOURCE_DEBUG;

typedef struct _RTL_CRITICAL_SECTION {
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    ULONG_PTR SpinCount;
} RTL_CRITICAL_SECTION, *PRTL_CRITICAL_SECTION;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _CURDIR {
    UNICODE_STRING DosPath;
    PVOID Handle;
} CURDIR, *PCURDIR;

typedef struct RTL_DRIVE_LETTER_CURDIR {
    USHORT              Flags;
    USHORT              Length;
    ULONG               TimeStamp;
    UNICODE_STRING      DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct tagRTL_BITMAP {
    ULONG  SizeOfBitMap;	/* Number of bits in the bitmap */
    PULONG Buffer; /* Bitmap data, assumed sized to a DWORD boundary */
} RTL_BITMAP, * PRTL_BITMAP;

typedef const RTL_BITMAP *PCRTL_BITMAP;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG               AllocationSize;
    ULONG               Size;
    ULONG               Flags;
    ULONG               DebugFlags;
    HANDLE              ConsoleHandle;
    ULONG               ConsoleFlags;
    HANDLE              hStdInput;
    HANDLE              hStdOutput;
    HANDLE              hStdError;
    CURDIR              CurrentDirectory;
    UNICODE_STRING      DllPath;
    UNICODE_STRING      ImagePathName;
    UNICODE_STRING      CommandLine;
    PWSTR               Environment;
    ULONG               dwX;
    ULONG               dwY;
    ULONG               dwXSize;
    ULONG               dwYSize;
    ULONG               dwXCountChars;
    ULONG               dwYCountChars;
    ULONG               dwFillAttribute;
    ULONG               dwFlags;
    ULONG               wShowWindow;
    UNICODE_STRING      WindowTitle;
    UNICODE_STRING      Desktop;
    UNICODE_STRING      ShellInfo;
    UNICODE_STRING      RuntimeInfo;
    RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
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

/*
 * Unicode routines
 */
VOID NTAPI RtlInitUnicodeString(IN OUT PUNICODE_STRING DestinationString,
				IN PCWSTR SourceString);

NTSTATUS NTAPI RtlInitUnicodeStringEx(OUT PUNICODE_STRING DestinationString,
				      IN PCWSTR SourceString);

NTSTATUS NTAPI RtlUnicodeToUTF8N(CHAR *utf8_dest, ULONG utf8_bytes_max,
                                 ULONG *utf8_bytes_written,
                                 const WCHAR *uni_src, ULONG uni_bytes);

NTSTATUS NTAPI RtlUTF8ToUnicodeN(WCHAR *uni_dest, ULONG uni_bytes_max,
                                 ULONG *uni_bytes_written,
                                 const CHAR *utf8_src, ULONG utf8_bytes);

/*
 * Structured exception handling routines
 */
VOID NTAPI RtlUnwind(IN PVOID TargetFrame OPTIONAL,
		     IN PVOID TargetIp OPTIONAL,
		     IN PEXCEPTION_RECORD ExceptionRecord OPTIONAL,
		     IN PVOID ReturnValue);

#ifdef _M_AMD64
VOID NTAPI RtlUnwindEx(IN PVOID TargetFrame OPTIONAL,
		       IN PVOID TargetIp OPTIONAL,
		       IN PEXCEPTION_RECORD ExceptionRecord OPTIONAL,
		       IN PVOID ReturnValue,
		       IN PCONTEXT ContextRecord,
		       IN PUNWIND_HISTORY_TABLE HistoryTable OPTIONAL);
#endif
