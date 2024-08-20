/*
 * Runtime library types and functions exported by NTDLL.
 * These are not defined for the NTOS root task.
 */

#pragma once

#ifdef _NTOSKRNL_
#error "Do not include <nturtl.h> for the NTOS root task"
#endif

#ifndef _MSC_VER
#error "Only PE targets support the APIs defined in this file."
#endif

#include <ntmmapi.h>
#include <ntpsapi.h>
#include <ntseapi.h>
#include <guiddef.h>

#define _NTURTL_H_

#define MAX_PATH		260
#define MAX_COMPUTERNAME_LENGTH 15

#define RTL_UNCHANGED_UNK_PATH  1
#define RTL_CONVERTED_UNC_PATH  2
#define RTL_CONVERTED_NT_PATH   3
#define RTL_UNCHANGED_DOS_PATH  4

#define RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK (0x00000001)

#define RTL_DRIVE_LETTER_VALID (USHORT)0x0001

/*
 * Unicode routine flags
 */
#define IS_TEXT_UNICODE_ASCII16 1
#define IS_TEXT_UNICODE_REVERSE_ASCII16 16
#define IS_TEXT_UNICODE_STATISTICS 2
#define IS_TEXT_UNICODE_REVERSE_STATISTICS 32
#define IS_TEXT_UNICODE_CONTROLS 4
#define IS_TEXT_UNICODE_REVERSE_CONTROLS 64
#define IS_TEXT_UNICODE_SIGNATURE 8
#define IS_TEXT_UNICODE_REVERSE_SIGNATURE 128
#define IS_TEXT_UNICODE_ILLEGAL_CHARS 256
#define IS_TEXT_UNICODE_ODD_LENGTH 512
#define IS_TEXT_UNICODE_DBCS_LEADBYTE 1024
#define IS_TEXT_UNICODE_NULL_BYTES 4096
#define IS_TEXT_UNICODE_UNICODE_MASK 15
#define IS_TEXT_UNICODE_REVERSE_MASK 240
#define IS_TEXT_UNICODE_NOT_UNICODE_MASK 3840
#define IS_TEXT_UNICODE_NOT_ASCII_MASK 61440

/* RtlCheckRegistryKey flags */
#define RTL_REGISTRY_ABSOLUTE             0
#define RTL_REGISTRY_SERVICES             1
#define RTL_REGISTRY_CONTROL              2
#define RTL_REGISTRY_WINDOWS_NT           3
#define RTL_REGISTRY_DEVICEMAP            4
#define RTL_REGISTRY_USER                 5
#define RTL_REGISTRY_MAXIMUM              6
#define RTL_REGISTRY_HANDLE               0x40000000
#define RTL_REGISTRY_OPTIONAL             0x80000000

/* RTL_QUERY_REGISTRY_TABLE.Flags */
#define RTL_QUERY_REGISTRY_SUBKEY         0x00000001
#define RTL_QUERY_REGISTRY_TOPKEY         0x00000002
#define RTL_QUERY_REGISTRY_REQUIRED       0x00000004
#define RTL_QUERY_REGISTRY_NOVALUE        0x00000008
#define RTL_QUERY_REGISTRY_NOEXPAND       0x00000010
#define RTL_QUERY_REGISTRY_DIRECT         0x00000020
#define RTL_QUERY_REGISTRY_DELETE         0x00000040
#define RTL_QUERY_REGISTRY_TYPECHECK      0x00000100

#define RTL_QUERY_REGISTRY_TYPECHECK_SHIFT 24

typedef NTSTATUS (NTAPI RTL_QUERY_REGISTRY_ROUTINE)(IN PWSTR ValueName,
						    IN ULONG ValueType,
						    IN PVOID ValueData,
						    IN ULONG ValueLength,
						    IN OPTIONAL PVOID Context,
						    IN OPTIONAL PVOID EntryContext);
typedef RTL_QUERY_REGISTRY_ROUTINE *PRTL_QUERY_REGISTRY_ROUTINE;

typedef struct _RTL_QUERY_REGISTRY_TABLE {
    PRTL_QUERY_REGISTRY_ROUTINE QueryRoutine;
    ULONG Flags;
    PCWSTR Name;
    PVOID EntryContext;
    ULONG DefaultType;
    PVOID DefaultData;
    ULONG DefaultLength;
} RTL_QUERY_REGISTRY_TABLE, *PRTL_QUERY_REGISTRY_TABLE;

/*
 * String Hash Algorithms
 */
#define HASH_STRING_ALGORITHM_DEFAULT                       0
#define HASH_STRING_ALGORITHM_X65599                        1
#define HASH_STRING_ALGORITHM_INVALID                       0xffffffff

/*
 * RtlDuplicateString Flags
 */
#define RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE         1
#define RTL_DUPLICATE_UNICODE_STRING_ALLOCATE_NULL_STRING   2

/*
 * RtlFindCharInUnicodeString Flags
 */
#define RTL_FIND_CHAR_IN_UNICODE_STRING_START_AT_END        1
#define RTL_FIND_CHAR_IN_UNICODE_STRING_COMPLEMENT_CHAR_SET 2
#define RTL_FIND_CHAR_IN_UNICODE_STRING_CASE_INSENSITIVE    4

/*
 * Auto-Managed Rtl* String Buffer
 */
typedef struct _RTL_BUFFER {
    PUCHAR Buffer;
    PUCHAR StaticBuffer;
    SIZE_T Size;
    SIZE_T StaticSize;
    SIZE_T ReservedForAllocatedSize;
    PVOID ReservedForIMalloc;
} RTL_BUFFER, *PRTL_BUFFER;

typedef struct _RTL_UNICODE_STRING_BUFFER {
    UNICODE_STRING String;
    RTL_BUFFER ByteBuffer;
    WCHAR MinimumStaticBufferForTerminalNul;
} RTL_UNICODE_STRING_BUFFER, *PRTL_UNICODE_STRING_BUFFER;

#define RTL_SKIP_BUFFER_COPY    0x00000001

typedef struct _COMPRESSED_DATA_INFO {
    USHORT CompressionFormatAndEngine;
    UCHAR CompressionUnitShift;
    UCHAR ChunkShift;
    UCHAR ClusterShift;
    UCHAR Reserved;
    USHORT NumberOfChunks;
    ULONG CompressedChunkSizes[ANYSIZE_ARRAY];
} COMPRESSED_DATA_INFO, *PCOMPRESSED_DATA_INFO;

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

#define RTL_MAX_DRIVE_LETTERS 32

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

typedef struct _ACTIVATION_CONTEXT_STACK {
    ULONG Flags;
    ULONG NextCookieSequenceNumber;
    RTL_ACTIVATION_CONTEXT_STACK_FRAME *ActiveFrame;
    LIST_ENTRY FrameListCache;
} ACTIVATION_CONTEXT_STACK, *PACTIVATION_CONTEXT_STACK;

typedef VOID (NTAPI *PPS_POST_PROCESS_INIT_ROUTINE)(VOID);
typedef VOID (NTAPI *PFLS_CALLBACK_FUNCTION)(PVOID);

/*
 * Fiber local storage data
 */
#define RTL_FLS_MAXIMUM_AVAILABLE 128
typedef struct _RTL_FLS_DATA {
    LIST_ENTRY ListEntry;
    PVOID Data[RTL_FLS_MAXIMUM_AVAILABLE];
} RTL_FLS_DATA, *PRTL_FLS_DATA;

#include <pshpack4.h>
typedef struct _PEB {                                                 /* win32/win64 */
    BOOLEAN                          InheritedAddressSpace;             /* 000/000 */
    BOOLEAN                          ReadImageFileExecOptions;          /* 001/001 */
    BOOLEAN                          BeingDebugged;                     /* 002/002 */
    BOOLEAN                          SpareBool;                         /* 003/003 */
    HANDLE                           Mutant;                            /* 004/008 */
    HMODULE                          ImageBaseAddress;                  /* 008/010 */
    PPEB_LDR_DATA                    LdrData;                           /* 00c/018 */
    RTL_USER_PROCESS_PARAMETERS     *ProcessParameters;                 /* 010/020 */
    PVOID                            SubSystemData;                     /* 014/028 */
    HANDLE                           ProcessHeap;                       /* 018/030 */
    struct _RTL_CRITICAL_SECTION    *FastPebLock;                       /* 01c/038 */
    PVOID /*PPEBLOCKROUTINE*/        FastPebLockRoutine;                /* 020/040 */
    PVOID /*PPEBLOCKROUTINE*/        FastPebUnlockRoutine;              /* 024/048 */
    ULONG                            EnvironmentUpdateCount;            /* 028/050 */
    PVOID                            KernelCallbackTable;               /* 02c/058 */
    ULONG                            Reserved[2];                       /* 030/060 */
    PVOID /*PPEB_FREE_BLOCK*/        FreeList;                          /* 038/068 */
    ULONG                            TlsExpansionCounter;               /* 03c/070 */
    PRTL_BITMAP                      TlsBitmap;                         /* 040/078 */
    ULONG                            TlsBitmapBits[2];                  /* 044/080 */
    PVOID                            ReadOnlySharedMemoryBase;          /* 04c/088 */
    PVOID                            ReadOnlySharedMemoryHeap;          /* 050/090 */
    PVOID                           *ReadOnlyStaticServerData;          /* 054/098 */
    PVOID                            AnsiCodePageData;                  /* 058/0a0 */
    PVOID                            OemCodePageData;                   /* 05c/0a8 */
    PVOID                            UnicodeCaseTableData;              /* 060/0b0 */
    ULONG                            NumberOfProcessors;                /* 064/0b8 */
    ULONG                            NtGlobalFlag;                      /* 068/0bc */
    LARGE_INTEGER                    CriticalSectionTimeout;            /* 070/0c0 */
    SIZE_T                           HeapSegmentReserve;                /* 078/0c8 */
    SIZE_T                           HeapSegmentCommit;                 /* 07c/0d0 */
    SIZE_T                           HeapDeCommitTotalFreeThreshold;    /* 080/0d8 */
    SIZE_T                           HeapDeCommitFreeBlockThreshold;    /* 084/0e0 */
    ULONG                            NumberOfHeaps;                     /* 088/0e8 */
    ULONG                            MaximumNumberOfHeaps;              /* 08c/0ec */
    PVOID                           *ProcessHeaps;                      /* 090/0f0 */
    PVOID                            GdiSharedHandleTable;              /* 094/0f8 */
    PVOID                            ProcessStarterHelper;              /* 098/100 */
    PVOID                            GdiDCAttributeList;                /* 09c/108 */
    PVOID                            LoaderLock;                        /* 0a0/110 */
    ULONG                            OSMajorVersion;                    /* 0a4/118 */
    ULONG                            OSMinorVersion;                    /* 0a8/11c */
    ULONG                            OSBuildNumber;                     /* 0ac/120 */
    ULONG                            OSPlatformId;                      /* 0b0/124 */
    ULONG                            ImageSubSystem;                    /* 0b4/128 */
    ULONG                            ImageSubSystemMajorVersion;        /* 0b8/12c */
    ULONG                            ImageSubSystemMinorVersion;        /* 0bc/130 */
    ULONG                            ImageProcessAffinityMask;          /* 0c0/134 */
    HANDLE                           GdiHandleBuffer[28];               /* 0c4/138 */
    ULONG                            Unknown[6];                        /* 134/218 */
    PPS_POST_PROCESS_INIT_ROUTINE    PostProcessInitRoutine;            /* 14c/230 */
    PRTL_BITMAP                      TlsExpansionBitmap;                /* 150/238 */
    ULONG                            TlsExpansionBitmapBits[32];        /* 154/240 */
    ULONG                            SessionId;                         /* 1d4/2c0 */
    ULARGE_INTEGER                   AppCompatFlags;                    /* 1d8/2c8 */
    ULARGE_INTEGER                   AppCompatFlagsUser;                /* 1e0/2d0 */
    PVOID                            ShimData;                          /* 1e8/2d8 */
    PVOID                            AppCompatInfo;                     /* 1ec/2e0 */
    UNICODE_STRING                   CSDVersion;                        /* 1f0/2e8 */
    PVOID                            ActivationContextData;             /* 1f8/2f8 */
    PVOID                            ProcessAssemblyStorageMap;         /* 1fc/300 */
    PVOID                            SystemDefaultActivationData;       /* 200/308 */
    PVOID                            SystemAssemblyStorageMap;          /* 204/310 */
    SIZE_T                           MinimumStackCommit;                /* 208/318 */
    PFLS_CALLBACK_FUNCTION          *FlsCallback;                       /* 20c/320 */
    LIST_ENTRY                       FlsListHead;                       /* 210/328 */
    PRTL_BITMAP                      FlsBitmap;                         /* 218/338 */
    ULONG                            FlsBitmapBits[4];                  /* 21c/340 */
    ULONG                            FlsHighIndex;                      /* 22c/350 */
    LCID                             SessionDefaultLocale;              /* 230/358 */
} PEB, *PPEB;
#include <poppack.h>

C_ASSERT(sizeof(PEB) < PAGE_SIZE);

#include <pshpack4.h>
typedef struct _TEB {                                        /* win32/win64 */
    NT_TIB                  NtTib;                             /* 000/000 */
    PVOID                   SparePointer;                      /* 028/050 */
    PVOID                   ThreadLocalStoragePointer;         /* 02c/058 */
    PPEB                    ProcessEnvironmentBlock;           /* 030/060 */
    ULONG                   LastErrorValue;                    /* 034/068 */
    ULONG                   LastStatusValue;                   /* 038/06c */
    PVOID                   CsrClientThread;                   /* 03c/070 */
    ULONG                   CurrentLocale;                     /* 040/078 */
    ULONG                   HardErrorMode;                     /* 044/07c */
    PVOID                   DeallocationStack;                 /* 048/080 */
    PRTL_FLS_DATA           FlsData;                           /* 04c/088 */
    PVOID                   TlsSlots[64];                      /* 050/090 */
    LIST_ENTRY              TlsLinks;                          /* 150/290 */
    PVOID                  *TlsExpansionSlots;                 /* 158/300 */
    PVOID                   DebuggerHandle;                    /* 15c/308 */
    union {
	struct {
	    ULONG_PTR       ServiceCap;                        /* 160/310 */
	    PVOID           CoroutineStackLow;                 /* 164/318 */
	    PVOID           CoroutineStackHigh;                /* 168/320 */
	    BOOLEAN         DpcQueued;			       /* 16c/328 */
	    BOOLEAN         IoWorkItemQueued;		       /* 16d/329 */
	    BOOLEAN         EventSignaled;		       /* 16e/32a */
	    BOOLEAN         IsDpcThread;		       /* 16f/32b */
	    BOOLEAN         IsIsrThread;		       /* 170/32c */
	} Wdm;
	struct {
            CLIENT_ID       RealClientId;                      /* 160/310 */
	    PVOID           ThreadInfo;                        /* 168/320 */
	    ULONG           ClientInfo[31];                    /* 1e8/328 (user32) */
            ULONG           GuaranteedStackBytes;              /* 1ec/3a4 */
	    PVOID           SystemReserved1[54];               /* 1f0/3b0 (kernel32) */
	    UNICODE_STRING  StaticUnicodeString;               /* 2c8/560 (advapi32) */
	    WCHAR           StaticUnicodeBuffer[261];          /* 2d0/570 (advapi32) */
	} Win32;
    };
} TEB, *PTEB;
#include <poppack.h>

C_ASSERT(sizeof(TEB) < PAGE_SIZE);

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
 * End of Exception List
 */
#define EXCEPTION_CHAIN_END		((PEXCEPTION_REGISTRATION_RECORD)-1)

/*
 * Exception registration record
 */
typedef struct _EXCEPTION_REGISTRATION_RECORD {
    struct _EXCEPTION_REGISTRATION_RECORD *Next;
    PEXCEPTION_ROUTINE Handler;
} EXCEPTION_REGISTRATION_RECORD, *PEXCEPTION_REGISTRATION_RECORD;

/*
 * Exception pointers
 */
typedef struct _EXCEPTION_POINTERS {
  PEXCEPTION_RECORD ExceptionRecord;
  PCONTEXT ContextRecord;
} EXCEPTION_POINTERS, *PEXCEPTION_POINTERS;

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
 * Exception Code
 */
#define EXCEPTION_ACCESS_VIOLATION		STATUS_ACCESS_VIOLATION
#define EXCEPTION_DATATYPE_MISALIGNMENT		STATUS_DATATYPE_MISALIGNMENT
#define EXCEPTION_BREAKPOINT			STATUS_BREAKPOINT
#define EXCEPTION_SINGLE_STEP			STATUS_SINGLE_STEP
#define EXCEPTION_ARRAY_BOUNDS_EXCEEDED		STATUS_ARRAY_BOUNDS_EXCEEDED
#define EXCEPTION_FLT_DENORMAL_OPERAND		STATUS_FLOAT_DENORMAL_OPERAND
#define EXCEPTION_FLT_DIVIDE_BY_ZERO		STATUS_FLOAT_DIVIDE_BY_ZERO
#define EXCEPTION_FLT_INEXACT_RESULT		STATUS_FLOAT_INEXACT_RESULT
#define EXCEPTION_FLT_INVALID_OPERATION		STATUS_FLOAT_INVALID_OPERATION
#define EXCEPTION_FLT_OVERFLOW			STATUS_FLOAT_OVERFLOW
#define EXCEPTION_FLT_STACK_CHECK		STATUS_FLOAT_STACK_CHECK
#define EXCEPTION_FLT_UNDERFLOW			STATUS_FLOAT_UNDERFLOW
#define EXCEPTION_INT_DIVIDE_BY_ZERO		STATUS_INTEGER_DIVIDE_BY_ZERO
#define EXCEPTION_INT_OVERFLOW			STATUS_INTEGER_OVERFLOW
#define EXCEPTION_PRIV_INSTRUCTION		STATUS_PRIVILEGED_INSTRUCTION
#define EXCEPTION_IN_PAGE_ERROR			STATUS_IN_PAGE_ERROR
#define EXCEPTION_ILLEGAL_INSTRUCTION		STATUS_ILLEGAL_INSTRUCTION
#define EXCEPTION_NONCONTINUABLE_EXCEPTION	STATUS_NONCONTINUABLE_EXCEPTION
#define EXCEPTION_STACK_OVERFLOW		STATUS_STACK_OVERFLOW
#define EXCEPTION_INVALID_DISPOSITION		STATUS_INVALID_DISPOSITION
#define EXCEPTION_GUARD_PAGE			STATUS_GUARD_PAGE_VIOLATION
#define EXCEPTION_INVALID_HANDLE		STATUS_INVALID_HANDLE
#define CONTROL_C_EXIT				STATUS_CONTROL_C_EXIT

/*
 * Data structures for table-based structured exception handling
 */
#ifndef _M_IX86

#define UNW_FLAG_NHANDLER 0x0
#define UNW_FLAG_EHANDLER 0x1
#define UNW_FLAG_UHANDLER 0x2

typedef PRUNTIME_FUNCTION GET_RUNTIME_FUNCTION_CALLBACK(IN DWORD64 ControlPc,
							IN OPTIONAL PVOID Context);
typedef GET_RUNTIME_FUNCTION_CALLBACK *PGET_RUNTIME_FUNCTION_CALLBACK;

#define UNWIND_HISTORY_TABLE_SIZE 12

typedef struct _UNWIND_HISTORY_TABLE_ENTRY {
    ULONG64 ImageBase;
    PRUNTIME_FUNCTION FunctionEntry;
} UNWIND_HISTORY_TABLE_ENTRY, *PUNWIND_HISTORY_TABLE_ENTRY;

#define UNWIND_HISTORY_TABLE_NONE 0
#define UNWIND_HISTORY_TABLE_GLOBAL 1
#define UNWIND_HISTORY_TABLE_LOCAL 2

typedef struct _UNWIND_HISTORY_TABLE {
    ULONG Count;
    BYTE  LocalHint;
    BYTE  GlobalHint;
    BYTE  Search;
    BYTE  Once;
    ULONG64 LowAddress;
    ULONG64 HighAddress;
    UNWIND_HISTORY_TABLE_ENTRY Entry[UNWIND_HISTORY_TABLE_SIZE];
} UNWIND_HISTORY_TABLE, *PUNWIND_HISTORY_TABLE;

typedef struct _DISPATCHER_CONTEXT {
    ULONG64 ControlPc;
    ULONG64 ImageBase;
    PRUNTIME_FUNCTION FunctionEntry;
    ULONG64 EstablisherFrame;
    ULONG64 TargetIp;
    PCONTEXT ContextRecord;
    PEXCEPTION_ROUTINE LanguageHandler;
    PVOID HandlerData;
    struct _UNWIND_HISTORY_TABLE *HistoryTable;
    ULONG ScopeIndex;
#ifdef _M_AMD64
    ULONG Fill0;
#elif defined(_M_ARM64)
    BOOLEAN ControlPcIsUnwound;
    PBYTE NonVolatileRegisters;
#else
#error "Unsupported architecture"
#endif
} DISPATCHER_CONTEXT, *PDISPATCHER_CONTEXT;

typedef struct _SCOPE_TABLE {
    ULONG Count;
    struct {
        ULONG BeginAddress;
        ULONG EndAddress;
        ULONG HandlerAddress;
        ULONG JumpTarget;
    } ScopeRecord[1];
} SCOPE_TABLE, *PSCOPE_TABLE;

typedef LONG (*PEXCEPTION_FILTER)(PEXCEPTION_POINTERS ExceptionPointers,
				  PVOID EstablisherFrame);

typedef VOID (*PTERMINATION_HANDLER)(BOOLEAN TerminationIsAbnormal,
				     PVOID EstablisherFrame);

#endif	/* !defined(_M_IX86) */

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

typedef union DECLSPEC_ALIGN(16) _SLIST_HEADER {
    struct {
	ULONGLONG Alignment;
	ULONGLONG Region;
    };
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

#else  /* WIN32 */

#define SLIST_ENTRY SINGLE_LIST_ENTRY
#define _SLIST_ENTRY _SINGLE_LIST_ENTRY
#define PSLIST_ENTRY PSINGLE_LIST_ENTRY

typedef union _SLIST_HEADER {
    ULONGLONG Alignment;
    struct {
	SLIST_ENTRY Next;
	USHORT Depth;
	USHORT Sequence;
    };
} SLIST_HEADER, *PSLIST_HEADER;

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

#define  RTL_GENERIC_COMPARE_ROUTINE     RTL_AVL_COMPARE_ROUTINE
#define PRTL_GENERIC_COMPARE_ROUTINE    PRTL_AVL_COMPARE_ROUTINE
#define  RTL_GENERIC_ALLOCATE_ROUTINE    RTL_AVL_ALLOCATE_ROUTINE
#define PRTL_GENERIC_ALLOCATE_ROUTINE   PRTL_AVL_ALLOCATE_ROUTINE
#define  RTL_GENERIC_FREE_ROUTINE        RTL_AVL_FREE_ROUTINE
#define PRTL_GENERIC_FREE_ROUTINE       PRTL_AVL_FREE_ROUTINE

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
 * Slim Read/Write lock
 */
#define RTL_SRWLOCK_INIT {0}

typedef struct _RTL_SRWLOCK {
    PVOID Ptr;
} RTL_SRWLOCK, *PRTL_SRWLOCK;

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
 * Timezone Information
 */
typedef struct _RTL_TIME_ZONE_INFORMATION {
    LONG Bias;
    WCHAR StandardName[32];
    TIME_FIELDS StandardDate;
    LONG StandardBias;
    WCHAR DaylightName[32];
    TIME_FIELDS DaylightDate;
    LONG DaylightBias;
} RTL_TIME_ZONE_INFORMATION, *PRTL_TIME_ZONE_INFORMATION;

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

NTAPI NTSYSAPI NTSTATUS LdrQueryImageFileKeyOption(IN HANDLE KeyHandle,
						   IN PCWSTR ValueName,
						   IN ULONG Type,
						   OUT PVOID Buffer,
						   IN ULONG BufferSize,
						   OUT OPTIONAL PULONG ReturnedLength);

NTAPI NTSYSAPI NTSTATUS LdrQueryImageFileExecutionOptions(IN PUNICODE_STRING SubKey,
							  IN PCWSTR ValueName,
							  IN ULONG ValueSize,
							  OUT PVOID Buffer,
							  IN ULONG BufferSize,
							  OUT OPTIONAL PULONG ReturnedLength);

/*
 * Message Resource Flag
 */
#define MESSAGE_RESOURCE_UNICODE                            0x0001

/*
 * Message Resource Entry, Block and Data
 */
typedef struct _MESSAGE_RESOURCE_ENTRY {
    USHORT Length;
    USHORT Flags;
    UCHAR Text[];
} MESSAGE_RESOURCE_ENTRY, *PMESSAGE_RESOURCE_ENTRY;

typedef struct _MESSAGE_RESOURCE_BLOCK {
    ULONG LowId;
    ULONG HighId;
    ULONG OffsetToEntries;
} MESSAGE_RESOURCE_BLOCK, *PMESSAGE_RESOURCE_BLOCK;

typedef struct _MESSAGE_RESOURCE_DATA {
    ULONG NumberOfBlocks;
    MESSAGE_RESOURCE_BLOCK Blocks[];
} MESSAGE_RESOURCE_DATA, *PMESSAGE_RESOURCE_DATA;

/*
 * Message Resource Functions
 */
NTAPI NTSYSAPI NTSTATUS RtlFindMessage(IN PVOID BaseAddress,
				       IN ULONG Type,
				       IN ULONG Language,
				       IN ULONG MessageId,
				       OUT PMESSAGE_RESOURCE_ENTRY *MessageResourceEntry);

/*
 * Resource Functions
 */
NTAPI NTSTATUS LdrAccessResource(IN PVOID BaseAddress,
				 IN PIMAGE_RESOURCE_DATA_ENTRY ResourceDataEntry,
				 OUT OPTIONAL PVOID *Resource,
				 OUT OPTIONAL PULONG Size);

NTAPI NTSTATUS LdrFindResource_U(IN PVOID BaseAddress,
				 IN PLDR_RESOURCE_INFO ResourceInfo,
				 IN ULONG Level,
				 OUT PIMAGE_RESOURCE_DATA_ENTRY *ResourceDataEntry);

NTAPI NTSTATUS LdrEnumResources(IN PVOID BaseAddress,
				IN PLDR_RESOURCE_INFO ResourceInfo,
				IN ULONG Level,
				IN OUT ULONG *ResourceCount,
				OUT LDR_ENUM_RESOURCE_INFO *Resources);

NTAPI NTSTATUS LdrFindResourceDirectory_U(IN PVOID BaseAddress,
					  IN PLDR_RESOURCE_INFO ResourceInfo,
					  IN ULONG Level,
					  OUT PIMAGE_RESOURCE_DIRECTORY *ResourceDirectory);

NTAPI NTSTATUS LdrLoadAlternateResourceModule(IN PVOID Module,
					      IN PWSTR Buffer);

NTAPI BOOLEAN LdrUnloadAlternateResourceModule(IN PVOID BaseAddress);

/*
 * Unicode string functions
 */
NTAPI NTSYSAPI VOID RtlInitUnicodeString(IN OUT PUNICODE_STRING DestinationString,
					 IN PCWSTR SourceString);

NTAPI NTSYSAPI NTSTATUS RtlInitUnicodeStringEx(OUT PUNICODE_STRING DestinationString,
					       IN PCWSTR SourceString);

NTAPI NTSYSAPI NTSTATUS RtlAppendUnicodeStringToString(IN OUT PUNICODE_STRING Destination,
						       IN PCUNICODE_STRING Source);

NTAPI NTSYSAPI LONG RtlCompareUnicodeString(IN PCUNICODE_STRING String1,
					    IN PCUNICODE_STRING String2,
					    IN BOOLEAN CaseInSensitive);

NTAPI NTSYSAPI VOID RtlFreeUnicodeString(IN PUNICODE_STRING UnicodeString);

NTAPI NTSYSAPI  BOOLEAN RtlEqualUnicodeString(IN PCUNICODE_STRING s1,
					      IN PCUNICODE_STRING s2,
					      IN BOOLEAN CaseInsensitive);

NTAPI NTSYSAPI NTSTATUS RtlIntegerToUnicode(IN ULONG Value,
					    IN ULONG Base OPTIONAL,
					    IN ULONG Length OPTIONAL,
					    IN OUT LPWSTR String);

NTAPI NTSYSAPI NTSTATUS RtlIntegerToUnicodeString(IN ULONG Value,
						  IN ULONG Base OPTIONAL,
						  IN OUT PUNICODE_STRING String);

NTAPI NTSYSAPI NTSTATUS RtlInt64ToUnicodeString(IN ULONGLONG Value,
						IN ULONG Base OPTIONAL,
						IN OUT PUNICODE_STRING String);

NTAPI NTSYSAPI BOOLEAN RtlPrefixUnicodeString(PCUNICODE_STRING String1,
					      PCUNICODE_STRING String2,
					      BOOLEAN CaseInsensitive);

NTAPI NTSYSAPI NTSTATUS RtlUnicodeStringToInteger(const UNICODE_STRING * str,	/* [I] Unicode string to be converted */
						  ULONG base,	/* [I] Number base for conversion (allowed 0, 2, 8, 10 or 16) */
						  ULONG * value);

NTAPI NTSYSAPI NTSTATUS RtlUnicodeStringToAnsiString(IN OUT PANSI_STRING AnsiDest,
						     IN PCUNICODE_STRING UniSource,
						     IN BOOLEAN AllocateDestinationString);

NTAPI NTSYSAPI BOOLEAN RtlIsTextUnicode(CONST VOID *buf,
					INT len,
					INT *pf);

NTAPI NTSYSAPI BOOLEAN RtlEqualComputerName(IN PUNICODE_STRING ComputerName1,
					    IN PUNICODE_STRING ComputerName2);

NTAPI NTSYSAPI BOOLEAN RtlEqualDomainName(IN PUNICODE_STRING DomainName1,
					  IN PUNICODE_STRING DomainName2);

NTAPI NTSYSAPI VOID RtlEraseUnicodeString(IN PUNICODE_STRING String);

NTAPI NTSYSAPI NTSTATUS RtlHashUnicodeString(IN CONST UNICODE_STRING *String,
					     IN BOOLEAN CaseInSensitive,
					     IN ULONG HashAlgorithm,
					     OUT PULONG HashValue);

NTAPI NTSYSAPI NTSTATUS RtlUpcaseUnicodeString(IN OUT PUNICODE_STRING UniDest,
					       IN PCUNICODE_STRING UniSource,
					       IN BOOLEAN AllocateDestinationString);

NTAPI NTSYSAPI NTSTATUS RtlUpcaseUnicodeStringToAnsiString(IN OUT PANSI_STRING AnsiDest,
							   IN PCUNICODE_STRING UniSource,
							   IN BOOLEAN AllocateDestinationString);

NTAPI NTSYSAPI NTSTATUS RtlDowncaseUnicodeString(IN OUT PUNICODE_STRING UniDest,
						 IN PCUNICODE_STRING UniSource,
						 IN BOOLEAN AllocateDestinationString);

NTAPI NTSYSAPI NTSTATUS RtlStringFromGUID(IN REFGUID Guid,
					  OUT PUNICODE_STRING GuidString);

NTAPI NTSYSAPI ULONG RtlUnicodeStringToAnsiSize(IN PCUNICODE_STRING UnicodeString);

NTAPI NTSYSAPI ULONG RtlxUnicodeStringToAnsiSize(IN PCUNICODE_STRING UnicodeString);

NTAPI NTSYSAPI ULONG RtlUnicodeStringToAnsiSize(IN PCUNICODE_STRING UnicodeString);

NTAPI NTSYSAPI VOID RtlCopyUnicodeString(IN OUT PUNICODE_STRING DestinationString,
					 IN PCUNICODE_STRING SourceString);

NTAPI NTSYSAPI BOOLEAN RtlCreateUnicodeString(IN OUT PUNICODE_STRING UniDest,
					      IN PCWSTR Source);

NTAPI NTSYSAPI BOOLEAN RtlCreateUnicodeStringFromAsciiz(OUT PUNICODE_STRING Destination,
							IN PCSZ Source);

NTAPI NTSYSAPI NTSTATUS RtlAppendUnicodeToString(IN OUT PUNICODE_STRING Destination,
						 IN PCWSTR Source);

NTAPI NTSYSAPI NTSTATUS RtlDuplicateUnicodeString(IN ULONG Flags,
						  IN PCUNICODE_STRING SourceString,
						  OUT PUNICODE_STRING DestinationString);

NTAPI NTSYSAPI NTSTATUS RtlValidateUnicodeString(IN ULONG Flags,
						 IN PCUNICODE_STRING String);

NTAPI NTSYSAPI NTSTATUS RtlFindCharInUnicodeString(IN ULONG Flags,
						   IN PCUNICODE_STRING SearchString,
						   IN PCUNICODE_STRING MatchString,
						   OUT PUSHORT Position);

NTAPI NTSYSAPI NTSTATUS RtlDnsHostNameToComputerName(PUNICODE_STRING ComputerName,
						     PUNICODE_STRING DnsHostName,
						     BOOLEAN AllocateComputerNameString);

/*
 * Unicode string inline functions
 */
FORCEINLINE NTAPI VOID RtlInitEmptyUnicodeString(OUT PUNICODE_STRING UnicodeString,
						 IN PWCHAR Buffer,
						 IN USHORT BufferSize)
{
    UnicodeString->Length = 0;
    UnicodeString->MaximumLength = BufferSize;
    UnicodeString->Buffer = Buffer;
}

/*
 * Ansi string functions
 */
NTAPI NTSYSAPI VOID RtlInitAnsiString(OUT PANSI_STRING DestinationString,
				      IN OPTIONAL PCSZ SourceString);

NTAPI NTSYSAPI NTSTATUS RtlInitAnsiStringEx(OUT PANSI_STRING DestinationString,
					    IN OPTIONAL PCSZ SourceString);

NTAPI NTSYSAPI VOID RtlInitString(IN OUT PSTRING DestinationString,
				  IN PCSZ SourceString);

NTAPI NTSYSAPI WCHAR RtlAnsiCharToUnicodeChar(IN OUT PUCHAR *AnsiChar);

NTAPI NTSYSAPI NTSTATUS RtlAnsiStringToUnicodeString(IN OUT PUNICODE_STRING UniDest,
						     IN PANSI_STRING AnsiSource,
						     IN BOOLEAN AllocateDestinationString);

NTAPI NTSYSAPI ULONG RtlAnsiStringToUnicodeSize(IN PCANSI_STRING AnsiString);

NTAPI NTSYSAPI NTSTATUS RtlAppendStringToString(IN PSTRING Destination,
						IN const STRING *Source);

NTAPI NTSYSAPI LONG RtlCompareString(IN const STRING * s1,
				     IN const STRING * s2,
				     IN BOOLEAN CaseInsensitive);

NTAPI NTSYSAPI BOOLEAN RtlEqualString(IN const STRING * s1,
				      IN const STRING * s2,
				      IN BOOLEAN CaseInsensitive);

NTAPI NTSYSAPI VOID RtlCopyString(IN OUT PSTRING DestinationString,
				  IN OPTIONAL const STRING *SourceString);

NTAPI NTSYSAPI VOID RtlFreeAnsiString(IN PANSI_STRING AnsiString);

NTAPI NTSYSAPI BOOLEAN RtlPrefixString(const STRING *String1,
				       const STRING *String2,
				       BOOLEAN CaseInsensitive);

NTAPI NTSYSAPI NTSTATUS RtlAppendAsciizToString(IN OUT PSTRING Destination,
						IN PCSZ Source);

NTAPI NTSYSAPI VOID RtlUpperString(PSTRING DestinationString,
				   const STRING *SourceString);

/*
 * Ansi string inline functions
 */
FORCEINLINE NTAPI VOID RtlInitEmptyAnsiString(OUT PANSI_STRING AnsiString,
					      IN PCHAR Buffer,
					      IN USHORT BufferSize)
{
    AnsiString->Length = 0;
    AnsiString->MaximumLength = BufferSize;
    AnsiString->Buffer = Buffer;
}

/*
 * Single character functions
 */
NTAPI NTSYSAPI NTSTATUS RtlCharToInteger(IN PCSZ String,
					 IN ULONG Base,
					 OUT PULONG Value);

NTAPI NTSYSAPI BOOLEAN RtlIsValidOemCharacter(IN PWCHAR Char);

NTAPI NTSYSAPI NTSTATUS RtlIntegerToChar(ULONG value,	/* [I] Value to be converted */
					 ULONG base,	/* [I] Number base for conversion (allowed 0, 2, 8, 10 or 16) */
					 ULONG length,	/* [I] Length of the str buffer in bytes */
					 PCHAR str);

NTAPI NTSYSAPI NTSTATUS RtlLargeIntegerToChar(IN PLARGE_INTEGER Value,
					      IN ULONG Base,
					      IN ULONG Length,
					      IN OUT PCHAR String);

NTAPI NTSYSAPI CHAR RtlUpperChar(IN CHAR Source);

NTAPI NTSYSAPI WCHAR RtlUpcaseUnicodeChar(IN WCHAR Source);

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

NTAPI NTSYSAPI VOID RtlFreeOemString(IN POEM_STRING OemString);

NTAPI NTSYSAPI NTSTATUS RtlUnicodeToMultiByteSize(OUT PULONG MbSize,
						  IN PCWCH UnicodeString,
						  IN ULONG UnicodeSize);

NTAPI NTSYSAPI ULONG RtlUnicodeStringToOemSize(IN PCUNICODE_STRING UnicodeString);

NTAPI NTSYSAPI ULONG RtlxUnicodeStringToOemSize(IN PCUNICODE_STRING UnicodeString);

NTAPI NTSYSAPI ULONG RtlUnicodeStringToCountedOemSize(IN PCUNICODE_STRING UnicodeString);

NTAPI NTSYSAPI NTSTATUS RtlUnicodeStringToOemString(IN OUT POEM_STRING OemDest,
						    IN PCUNICODE_STRING UniSource,
						    IN BOOLEAN AllocateDestinationString);

NTAPI NTSYSAPI NTSTATUS RtlUnicodeStringToCountedOemString(IN OUT POEM_STRING OemDest,
							   IN PCUNICODE_STRING UniSource,
							   IN BOOLEAN AllocateDestinationString);

NTAPI NTSYSAPI NTSTATUS RtlUpcaseUnicodeStringToCountedOemString(IN OUT POEM_STRING OemDest,
								 IN PCUNICODE_STRING UniSource,
								 IN BOOLEAN AllocateDestinationString);

NTAPI NTSYSAPI NTSTATUS RtlUpcaseUnicodeStringToOemString(IN OUT POEM_STRING OemDest,
							  IN PCUNICODE_STRING UniSource,
							  IN BOOLEAN AllocateDestinationString);

NTAPI NTSYSAPI ULONG RtlOemStringToUnicodeSize(IN PCOEM_STRING OemString);

NTAPI NTSYSAPI ULONG RtlxOemStringToUnicodeSize(IN PCOEM_STRING OemString);

NTAPI NTSYSAPI NTSTATUS RtlOemStringToUnicodeString(IN OUT PUNICODE_STRING UniDest,
						    IN PCOEM_STRING OemSource,
						    IN BOOLEAN AllocateDestinationString);

NTAPI NTSYSAPI NTSTATUS RtlOemStringToCountedUnicodeString(IN OUT PUNICODE_STRING UniDest,
							   IN PCOEM_STRING OemSource,
							   IN BOOLEAN AllocateDestinationString);

NTAPI NTSYSAPI NTSTATUS RtlMultiByteToUnicodeN(OUT PWCH UnicodeString,
					       IN ULONG MaxBytesInUnicodeString,
					       OUT OPTIONAL PULONG BytesInUnicodeString,
					       IN const CHAR *MultiByteString,
					       IN ULONG BytesInMultiByteString);

NTAPI NTSYSAPI NTSTATUS RtlUnicodeToMultiByteN(OUT PCHAR MbString,
					       IN ULONG MbSize,
					       OUT PULONG ResultSize OPTIONAL,
					       IN PCWCH UnicodeString,
					       IN ULONG UnicodeSize);

NTAPI NTSYSAPI NTSTATUS RtlOemToUnicodeN(OUT PWCHAR UnicodeString,
					 IN ULONG UnicodeSize,
					 OUT PULONG ResultSize OPTIONAL,
					 IN PCCH OemString,
					 IN ULONG OemSize);

NTAPI NTSYSAPI NTSTATUS RtlMultiByteToUnicodeSize(OUT PULONG UnicodeSize,
						  IN PCSTR MbString,
						  IN ULONG MbSize);

NTAPI NTSYSAPI NTSTATUS RtlUnicodeToOemN(OUT PCHAR OemString,
					 IN ULONG OemSize,
					 OUT PULONG ResultSize OPTIONAL,
					 IN PCWCH UnicodeString,
					 IN ULONG UnicodeSize);

NTAPI NTSYSAPI NTSTATUS RtlUpcaseUnicodeToCustomCPN(IN PCPTABLEINFO CustomCP,
						    OUT PCHAR CustomString,
						    IN ULONG CustomSize,
						    OUT PULONG ResultSize OPTIONAL,
						    IN PWCHAR UnicodeString,
						    IN ULONG UnicodeSize);

NTAPI NTSYSAPI NTSTATUS RtlUpcaseUnicodeToMultiByteN(OUT PCHAR MbString,
						     IN ULONG MbSize,
						     OUT PULONG ResultSize OPTIONAL,
						     IN PCWCH UnicodeString,
						     IN ULONG UnicodeSize);

NTAPI NTSYSAPI NTSTATUS RtlUpcaseUnicodeToOemN(OUT PCHAR OemString,
					       IN ULONG OemSize,
					       OUT PULONG ResultSize OPTIONAL,
					       IN PCWCH UnicodeString,
					       IN ULONG UnicodeSize);

/*
 * DOS 8.3 File Name Helper Routines
 */
typedef struct _GENERATE_NAME_CONTEXT {
    USHORT Checksum;
    BOOLEAN CheckSumInserted;
    UCHAR NameLength;		/* Must be <= 8 */
    WCHAR NameBuffer[8];
    ULONG ExtensionLength;	/* Must be <= 4 */
    WCHAR ExtensionBuffer[4];
    ULONG LastIndexValue;
} GENERATE_NAME_CONTEXT, *PGENERATE_NAME_CONTEXT;

NTAPI NTSYSAPI VOID RtlGenerate8dot3Name(IN PUNICODE_STRING Name,
					 IN BOOLEAN AllowExtendedCharacters,
					 IN OUT PGENERATE_NAME_CONTEXT Context,
					 OUT PUNICODE_STRING Name8dot3);
NTAPI NTSYSAPI BOOLEAN RtlIsNameLegalDOS8Dot3(IN PCUNICODE_STRING Name,
					      IN OUT POEM_STRING OemName,
					      OUT OPTIONAL PBOOLEAN NameContainsSpaces);

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

#ifndef _M_IX86
NTAPI NTSYSAPI VOID RtlUnwindEx(IN PVOID TargetFrame OPTIONAL,
				IN PVOID TargetIp OPTIONAL,
				IN PEXCEPTION_RECORD ExceptionRecord OPTIONAL,
				IN PVOID ReturnValue,
				IN PCONTEXT ContextRecord,
				IN PUNWIND_HISTORY_TABLE HistoryTable OPTIONAL);

NTAPI NTSYSAPI VOID RtlRestoreContext(IN PCONTEXT ContextRecord,
				      OUT OPTIONAL PEXCEPTION_RECORD ExceptionRecord);

NTAPI NTSYSAPI PRUNTIME_FUNCTION RtlLookupFunctionEntry(IN DWORD64 ControlPc,
							OUT PDWORD64 ImageBase,
							IN OUT OPTIONAL PUNWIND_HISTORY_TABLE HistoryTable);

NTAPI NTSYSAPI PEXCEPTION_ROUTINE RtlVirtualUnwind(IN ULONG HandlerType,
						   IN ULONG64 ImageBase,
						   IN ULONG64 ControlPc,
						   IN PRUNTIME_FUNCTION FunctionEntry,
						   IN OUT PCONTEXT Context,
						   OUT PVOID *HandlerData,
						   OUT PULONG64 EstablisherFrame,
						   IN OUT OPTIONAL PKNONVOLATILE_CONTEXT_POINTERS ContextPointers);
#endif

NTAPI NTSYSAPI PVOID RtlPcToFileHeader(IN PVOID PcValue,
				       OUT PVOID* BaseOfImage);

NTAPI NTSYSAPI VOID RtlCaptureContext(OUT PCONTEXT ContextRecord);

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
 * Slim Read/Write lock functions
 */
NTAPI NTSYSAPI VOID RtlInitializeSRWLock(OUT PRTL_SRWLOCK SRWLock);

NTAPI NTSYSAPI VOID RtlAcquireSRWLockShared(IN OUT PRTL_SRWLOCK SRWLock);

NTAPI NTSYSAPI VOID RtlAcquireSRWLockExclusive(IN OUT PRTL_SRWLOCK SRWLock);

NTAPI NTSYSAPI VOID RtlReleaseSRWLockShared(IN OUT PRTL_SRWLOCK SRWLock);

NTAPI NTSYSAPI VOID RtlReleaseSRWLockExclusive(IN OUT PRTL_SRWLOCK SRWLock);

NTAPI NTSYSAPI BOOLEAN RtlTryAcquireSRWLockShared(PRTL_SRWLOCK SRWLock);

NTAPI NTSYSAPI BOOLEAN RtlTryAcquireSRWLockExclusive(PRTL_SRWLOCK SRWLock);

/*
 * Memory functions
 */

NTAPI NTSYSAPI SIZE_T RtlCompareMemory(IN const VOID *Source1,
				       IN const VOID *Source2,
				       IN SIZE_T Length);

NTAPI NTSYSAPI SIZE_T RtlCompareMemoryUlong(IN PVOID Source,
					    IN SIZE_T Length,
					    IN ULONG Value);

#ifdef _M_AMD64
FORCEINLINE NTAPI VOID RtlFillMemoryUlong(OUT PVOID Destination,
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

NTAPI NTSYSAPI ULONG RtlFindLongestRunClear(IN PRTL_BITMAP BitMapHeader,
					    OUT PULONG StartingIndex);

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
FORCEINLINE NTAPI BOOLEAN RtlCheckBit(IN PRTL_BITMAP BitMapHeader,
				      IN ULONG BitPosition)
{
    return BitTest64((LONG64 CONST*)BitMapHeader->Buffer, (LONG64)BitPosition);
}
#else
#define RtlCheckBit(BMH,BP) (((((PLONG)(BMH)->Buffer)[(BP)/32]) >> ((BP)%32)) & 0x1)
#endif /* _M_AMD64 */

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

/*
 * Debug functions
 */
NTAPI NTSYSAPI VOID DbgBreakPoint(VOID);

__cdecl NTSYSAPI ULONG DbgPrint(IN PCSTR Format, ...) __attribute__((format(printf, 1, 2)));

__cdecl NTSYSAPI ULONG DbgPrintEx(IN ULONG ComponentId,
				  IN ULONG Level,
				  IN PCSTR Format, ...) __attribute__((format(printf, 3, 4)));

NTAPI NTSYSAPI ULONG vDbgPrintEx(IN ULONG ComponentId,
				 IN ULONG Level,
				 IN PCCH Format,
				 IN va_list ap);

NTAPI NTSYSAPI ULONG RtlAssert(IN PVOID FailedAssertion,
			       IN PVOID FileName,
			       IN ULONG LineNumber,
			       IN OPTIONAL PCHAR Message);

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

FORCEINLINE NTAPI PTEB NtCurrentTeb(VOID)
{
    return (PVOID)NtCurrentTib();
}

FORCEINLINE NTAPI PPEB NtCurrentPeb(VOID)
{
    return NtCurrentTeb()->ProcessEnvironmentBlock;
}

#define RtlGetCurrentPeb NtCurrentPeb

NTAPI NTSYSAPI VOID RtlAcquirePebLock(VOID);

NTAPI NTSYSAPI VOID RtlReleasePebLock(VOID);

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

NTAPI NTSTATUS
RtlDestroyProcessParameters(IN PRTL_USER_PROCESS_PARAMETERS ProcessParameters);

NTAPI PRTL_USER_PROCESS_PARAMETERS
RtlDeNormalizeProcessParams(PRTL_USER_PROCESS_PARAMETERS Params);

NTAPI PRTL_USER_PROCESS_PARAMETERS
RtlNormalizeProcessParams(PRTL_USER_PROCESS_PARAMETERS Params);

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

NTAPI NTSYSAPI VOID RtlInitializeContext(IN HANDLE ProcessHandle,
					 OUT PCONTEXT ThreadContext,
					 IN OPTIONAL PVOID ThreadStartParam,
					 IN PTHREAD_START_ROUTINE ThreadStartAddress,
					 IN PINITIAL_TEB InitialTeb);

/*
 * Path routines
 */

NTAPI NTSYSAPI RTL_PATH_TYPE RtlDetermineDosPathNameType_Ustr(IN PCUNICODE_STRING PathString);

NTAPI NTSYSAPI ULONG RtlIsDosDeviceName_Ustr(IN PCUNICODE_STRING PathString);

NTAPI NTSYSAPI NTSTATUS RtlpCheckDeviceName(IN PUNICODE_STRING FileName,
					    IN ULONG Length,
					    OUT PBOOLEAN NameInvalid);

NTAPI NTSYSAPI NTSTATUS RtlGetLengthWithoutLastFullDosOrNtPathElement(IN ULONG Flags,
								      IN PCUNICODE_STRING Path,
								      OUT PULONG LengthOut);

NTAPI NTSYSAPI NTSTATUS RtlComputePrivatizedDllName_U(IN PUNICODE_STRING DllName,
						      IN OUT PUNICODE_STRING RealName,
						      IN OUT PUNICODE_STRING LocalName);

NTAPI NTSYSAPI ULONG RtlGetFullPathName_Ustr(IN PUNICODE_STRING FileName,
					     IN ULONG Size,
					     OUT PWSTR Buffer,
					     OUT OPTIONAL PCWSTR * ShortName,
					     OUT OPTIONAL PBOOLEAN InvalidName,
					     OUT RTL_PATH_TYPE * PathType);

NTAPI NTSYSAPI BOOLEAN RtlDosPathNameToRelativeNtPathName_Ustr(IN PCUNICODE_STRING DosName,
							       OUT PUNICODE_STRING NtName,
							       OUT PCWSTR *PartName,
							       OUT PRTL_RELATIVE_NAME_U RelativeName);

NTAPI NTSYSAPI BOOLEAN RtlDoesFileExists_UstrEx(IN PCUNICODE_STRING FileName,
						IN BOOLEAN SucceedIfBusy);

NTAPI NTSYSAPI BOOLEAN RtlDoesFileExists_UStr(IN PUNICODE_STRING FileName);

NTAPI NTSYSAPI BOOLEAN RtlDoesFileExists_UEx(IN PCWSTR FileName,
					     IN BOOLEAN SucceedIfBusy);

NTAPI NTSYSAPI VOID RtlReleaseRelativeName(IN PRTL_RELATIVE_NAME_U RelativeName);

NTAPI NTSYSAPI ULONG RtlGetLongestNtPathLength(VOID);

NTAPI NTSYSAPI NTSTATUS RtlGetLengthWithoutTrailingPathSeparators(IN ULONG Flags,
								  IN PCUNICODE_STRING PathString,
								  OUT PULONG Length);

NTAPI NTSYSAPI RTL_PATH_TYPE RtlDetermineDosPathNameType_U(IN PCWSTR Path);

NTAPI NTSYSAPI ULONG RtlIsDosDeviceName_U(IN PCWSTR Path);

NTAPI NTSYSAPI ULONG RtlGetCurrentDirectory_U(IN ULONG MaximumLength,
					      OUT PWSTR Buffer);

NTAPI NTSYSAPI NTSTATUS RtlSetCurrentDirectory_U(IN PUNICODE_STRING Path);

NTAPI NTSYSAPI ULONG RtlGetFullPathName_UEx(IN PWSTR FileName,
					    IN ULONG BufferLength,
					    OUT PWSTR Buffer,
					    OUT OPTIONAL PWSTR *FilePart,
					    OUT OPTIONAL RTL_PATH_TYPE *InputPathType);

NTAPI NTSYSAPI ULONG RtlGetFullPathName_U(IN PCWSTR FileName,
					  IN ULONG Size,
					  OUT PWSTR Buffer,
					  OUT OPTIONAL PWSTR *ShortName);

NTAPI NTSYSAPI BOOLEAN RtlDosPathNameToNtPathName_U(IN PCWSTR DosName,
						    OUT PUNICODE_STRING NtName,
						    OUT PCWSTR *PartName,
						    OUT PRTL_RELATIVE_NAME_U RelativeName);

NTAPI NTSYSAPI NTSTATUS RtlDosPathNameToNtPathName_U_WithStatus(IN PCWSTR DosName,
								OUT PUNICODE_STRING NtName,
								OUT PCWSTR *PartName,
								OUT PRTL_RELATIVE_NAME_U	RelativeName);

NTAPI NTSYSAPI BOOLEAN RtlDosPathNameToRelativeNtPathName_U(IN PCWSTR DosName,
							    OUT PUNICODE_STRING NtName,
							    OUT PCWSTR *PartName,
							    OUT PRTL_RELATIVE_NAME_U RelativeName);

NTAPI NTSYSAPI NTSTATUS RtlDosPathNameToRelativeNtPathName_U_WithStatus(IN PCWSTR DosName,
									OUT PUNICODE_STRING NtName,
									OUT PCWSTR *PartName,
									OUT PRTL_RELATIVE_NAME_U RelativeName);

NTAPI NTSYSAPI NTSTATUS RtlNtPathNameToDosPathName(IN ULONG Flags,
						   IN OUT PRTL_UNICODE_STRING_BUFFER Path,
						   OUT PULONG PathType,
						   PULONG Unknown);

NTAPI NTSYSAPI NTSTATUS RtlDosApplyFileIsolationRedirection_Ustr(IN ULONG Flags,
								 IN PUNICODE_STRING OriginalName,
								 IN PUNICODE_STRING Extension,
								 IN OUT PUNICODE_STRING StaticString,
								 IN OUT PUNICODE_STRING DynamicString,
								 IN OUT PUNICODE_STRING *NewName,
								 IN PULONG NewFlags,
								 IN PSIZE_T FileNameSize,
								 IN PSIZE_T RequiredLength);

NTAPI NTSYSAPI ULONG RtlDosSearchPath_U(IN PCWSTR Path,
					IN PCWSTR FileName,
					IN PCWSTR Extension,
					IN ULONG Size,
					IN PWSTR Buffer,
					OUT PWSTR *PartName);

NTAPI NTSYSAPI NTSTATUS RtlGetFullPathName_UstrEx(IN PUNICODE_STRING FileName,
						  IN PUNICODE_STRING StaticString,
						  IN PUNICODE_STRING DynamicString,
						  IN PUNICODE_STRING *StringUsed,
						  IN PSIZE_T FilePartSize,
						  OUT PBOOLEAN NameInvalid,
						  OUT RTL_PATH_TYPE *PathType,
						  OUT PSIZE_T LengthNeeded);

NTAPI NTSYSAPI NTSTATUS RtlDosSearchPath_Ustr(IN ULONG Flags,
					      IN PUNICODE_STRING PathString,
					      IN PUNICODE_STRING FileNameString,
					      IN PUNICODE_STRING ExtensionString,
					      IN PUNICODE_STRING CallerBuffer,
					      IN OUT PUNICODE_STRING DynamicString OPTIONAL,
					      OUT PUNICODE_STRING *FullNameOut OPTIONAL,
					      OUT PSIZE_T FilePartSize OPTIONAL,
					      OUT PSIZE_T LengthNeeded OPTIONAL);

NTAPI NTSYSAPI BOOLEAN RtlDoesFileExists_U(IN PCWSTR FileName);

/*
 * Environment routines
 */
NTAPI NTSYSAPI NTSTATUS RtlCreateEnvironment(BOOLEAN Inherit,
					     PWSTR *OutEnvironment);

NTAPI NTSYSAPI VOID RtlDestroyEnvironment(PWSTR Environment);

NTAPI NTSYSAPI NTSTATUS RtlExpandEnvironmentStrings_U(PWSTR Environment,
						      PUNICODE_STRING Source,
						      PUNICODE_STRING Destination,
						      PULONG Length);

NTAPI NTSYSAPI VOID RtlSetCurrentEnvironment(PWSTR NewEnvironment,
					     PWSTR *OldEnvironment);

NTAPI NTSYSAPI NTSTATUS RtlSetEnvironmentVariable(PWSTR *Environment,
						  PUNICODE_STRING Name,
						  PUNICODE_STRING Value);

NTAPI NTSYSAPI NTSTATUS RtlQueryEnvironmentVariable_U(PWSTR Environment,
						      PCUNICODE_STRING Name,
						      PUNICODE_STRING Value);

/*
 * RTL auto-managed string buffer functions
 */
FORCEINLINE NTAPI VOID RtlInitBuffer(IN OUT PRTL_BUFFER Buffer,
				     IN PUCHAR Data,
				     IN ULONG DataSize)
{
    Buffer->Buffer = Buffer->StaticBuffer = Data;
    Buffer->Size = Buffer->StaticSize = DataSize;
    Buffer->ReservedForAllocatedSize = 0;
    Buffer->ReservedForIMalloc = NULL;
}

NTAPI NTSYSAPI NTSTATUS RtlEnsureBufferSize(IN ULONG Flags,
					    IN OUT PRTL_BUFFER Buffer,
					    IN SIZE_T RequiredSize);

FORCEINLINE NTAPI VOID RtlFreeBuffer(IN OUT PRTL_BUFFER Buffer)
{
    if (Buffer->Buffer != Buffer->StaticBuffer && Buffer->Buffer)
        RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer->Buffer);
    Buffer->Buffer = Buffer->StaticBuffer;
    Buffer->Size = Buffer->StaticSize;
}

/*
 * Time Functions
 */
NTAPI NTSYSAPI BOOLEAN RtlCutoverTimeToSystemTime(IN PTIME_FIELDS CutoverTimeFields,
						  OUT PLARGE_INTEGER SystemTime,
						  IN PLARGE_INTEGER CurrentTime,
						  IN BOOLEAN ThisYearsCutoverOnly);

NTAPI NTSYSAPI NTSTATUS RtlQueryTimeZoneInformation(OUT PRTL_TIME_ZONE_INFORMATION TimeZoneInformation);

NTAPI NTSYSAPI VOID RtlSecondsSince1970ToTime(IN ULONG SecondsSince1970,
					      OUT PLARGE_INTEGER Time);

NTAPI NTSYSAPI NTSTATUS RtlSetTimeZoneInformation(IN PRTL_TIME_ZONE_INFORMATION TimeZoneInformation);

NTAPI NTSYSAPI BOOLEAN RtlTimeFieldsToTime(IN PTIME_FIELDS TimeFields,
					   OUT PLARGE_INTEGER Time);

NTAPI NTSYSAPI BOOLEAN RtlTimeToSecondsSince1970(IN PLARGE_INTEGER Time,
						 OUT PULONG ElapsedSeconds);

NTAPI NTSYSAPI VOID RtlTimeToTimeFields(IN PLARGE_INTEGER Time,
					OUT PTIME_FIELDS TimeFields);

NTAPI NTSYSAPI NTSTATUS RtlSystemTimeToLocalTime(IN PLARGE_INTEGER SystemTime,
						 OUT PLARGE_INTEGER LocalTime);

NTAPI NTSYSAPI NTSTATUS RtlLocalTimeToSystemTime(IN PLARGE_INTEGER LocalTime,
						 OUT PLARGE_INTEGER SystemTime);

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

NTAPI NTSTATUS LdrLoadDll(IN OPTIONAL PWSTR SearchPath,
			  IN OPTIONAL PULONG DllCharacteristics,
			  IN PUNICODE_STRING DllName,
			  OUT PVOID *BaseAddress);

NTAPI NTSYSAPI NTSTATUS LdrUnloadDll(IN PVOID BaseAddress);

/*
 * LdrLockLoaderLock Flags
 */
#define LDR_LOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS   0x00000001
#define LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY          0x00000002

/*
 * LdrLockLoaderLock Dispositions
 */
#define LDR_LOCK_LOADER_LOCK_DISPOSITION_INVALID           0
#define LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED     1
#define LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_NOT_ACQUIRED 2

/*
 * LdrUnlockLoaderLock Flags
 */
#define LDR_UNLOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS 0x00000001

NTAPI NTSYSAPI NTSTATUS LdrLockLoaderLock(IN ULONG Flags,
					  OUT OPTIONAL PULONG Disposition,
					  OUT OPTIONAL PULONG_PTR Cookie);

NTAPI NTSYSAPI NTSTATUS LdrUnlockLoaderLock(IN ULONG Flags,
					    IN OPTIONAL ULONG_PTR Cookie);

/*
 * Registry routines
 */
NTAPI NTSYSAPI NTSTATUS RtlCheckRegistryKey(IN ULONG RelativeTo,
				   IN PWSTR Path);

NTAPI NTSYSAPI NTSTATUS RtlCreateRegistryKey(IN ULONG RelativeTo,
				    IN PWSTR Path);

NTAPI NTSYSAPI NTSTATUS RtlDeleteRegistryValue(IN ULONG RelativeTo,
				      IN PCWSTR Path,
				      IN PCWSTR ValueName);

NTAPI NTSYSAPI NTSTATUS RtlWriteRegistryValue(IN ULONG RelativeTo,
				     IN PCWSTR Path,
				     IN PCWSTR ValueName,
				     IN ULONG ValueType,
				     IN PVOID ValueData,
				     IN ULONG ValueLength);

NTAPI NTSYSAPI NTSTATUS RtlOpenCurrentUser(IN ACCESS_MASK DesiredAccess,
				  OUT PHANDLE KeyHandle);

NTAPI NTSYSAPI NTSTATUS RtlFormatCurrentUserKeyPath(OUT PUNICODE_STRING KeyPath);

NTAPI NTSYSAPI NTSTATUS RtlpNtCreateKey(OUT HANDLE KeyHandle,
			       IN ACCESS_MASK DesiredAccess,
			       IN POBJECT_ATTRIBUTES ObjectAttributes,
			       IN ULONG TitleIndex,
			       IN PUNICODE_STRING Class,
			       OUT PULONG Disposition);

NTAPI NTSYSAPI NTSTATUS RtlpNtEnumerateSubKey(IN HANDLE KeyHandle,
				     OUT PUNICODE_STRING SubKeyName,
				     IN ULONG Index,
				     IN ULONG Unused);

NTAPI NTSYSAPI NTSTATUS RtlpNtMakeTemporaryKey(IN HANDLE KeyHandle);

NTAPI NTSYSAPI NTSTATUS RtlpNtOpenKey(OUT HANDLE KeyHandle,
			     IN ACCESS_MASK DesiredAccess,
			     IN POBJECT_ATTRIBUTES ObjectAttributes,
			     IN ULONG Unused);

NTAPI NTSYSAPI NTSTATUS RtlpNtQueryValueKey(IN HANDLE KeyHandle,
				   OUT PULONG Type OPTIONAL,
				   OUT PVOID Data OPTIONAL,
				   IN OUT PULONG DataLength OPTIONAL,
				   IN ULONG Unused);

NTAPI NTSYSAPI NTSTATUS RtlpNtSetValueKey(IN HANDLE KeyHandle,
				 IN ULONG Type,
				 IN PVOID Data,
				 IN ULONG DataLength);

NTAPI NTSYSAPI NTSTATUS RtlQueryRegistryValues(IN ULONG RelativeTo,
				      IN PCWSTR Path,
				      IN PRTL_QUERY_REGISTRY_TABLE QueryTable,
				      IN PVOID Context,
				      IN PVOID Environment OPTIONAL);

/*
 * Security routines
 */
NTAPI NTSYSAPI NTSTATUS RtlAdjustPrivilege(IN ULONG Privilege,
					   IN BOOLEAN NewValue,
					   IN BOOLEAN ForThread,
					   OUT PBOOLEAN OldValue);

NTAPI NTSYSAPI BOOLEAN RtlValidSid(IN PSID Sid);

NTAPI NTSYSAPI ULONG RtlLengthRequiredSid(IN ULONG SubAuthorityCount);

NTAPI NTSYSAPI NTSTATUS RtlInitializeSid(IN PSID Sid,
					 IN PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
					 IN UCHAR SubAuthorityCount);

NTAPI NTSYSAPI PULONG RtlSubAuthoritySid(IN PSID Sid,
					 IN ULONG SubAuthority);

NTAPI NTSYSAPI PUCHAR RtlSubAuthorityCountSid(IN PSID Sid);

NTAPI NTSYSAPI PSID_IDENTIFIER_AUTHORITY RtlIdentifierAuthoritySid(IN PSID Sid);

NTAPI NTSYSAPI BOOLEAN RtlEqualSid(IN PSID Sid1,
				   IN PSID Sid2);

NTAPI NTSYSAPI ULONG RtlLengthSid(IN PSID Sid);

NTAPI NTSYSAPI NTSTATUS RtlCopySid(IN ULONG BufferLength,
				   IN PSID Dest,
				   IN PSID Src);

NTAPI NTSYSAPI PVOID RtlFreeSid(IN PSID Sid);

NTAPI NTSYSAPI BOOLEAN RtlEqualPrefixSid(IN PSID Sid1,
					 IN PSID Sid2);

NTAPI NTSYSAPI NTSTATUS RtlCopySidAndAttributesArray(IN ULONG Count,
						     IN PSID_AND_ATTRIBUTES Src,
						     IN ULONG SidAreaSize,
						     IN PSID_AND_ATTRIBUTES Dest,
						     IN PSID SidArea,
						     OUT PSID *RemainingSidArea,
						     OUT PULONG RemainingSidAreaSize);

NTAPI NTSYSAPI NTSTATUS RtlAllocateAndInitializeSid(IN PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
						    IN UCHAR SubAuthorityCount,
						    IN ULONG SubAuthority0,
						    IN ULONG SubAuthority1,
						    IN ULONG SubAuthority2,
						    IN ULONG SubAuthority3,
						    IN ULONG SubAuthority4,
						    IN ULONG SubAuthority5,
						    IN ULONG SubAuthority6,
						    IN ULONG SubAuthority7,
						    OUT PSID *Sid);

NTAPI NTSYSAPI NTSTATUS RtlConvertSidToUnicodeString(IN PUNICODE_STRING String,
						     IN PSID Sid,
						     IN BOOLEAN AllocateBuffer);

typedef struct _OSVERSIONINFO {
  ULONG dwOSVersionInfoSize;
  ULONG dwMajorVersion;
  ULONG dwMinorVersion;
  ULONG dwBuildNumber;
  ULONG dwPlatformId;
  WCHAR szCSDVersion[128];
} RTL_OSVERSIONINFO, *PRTL_OSVERSIONINFO;

typedef struct _OSVERSIONINFOEX {
    ULONG dwOSVersionInfoSize;
    ULONG dwMajorVersion;
    ULONG dwMinorVersion;
    ULONG dwBuildNumber;
    ULONG dwPlatformId;
    WCHAR szCSDVersion[128];
    USHORT wServicePackMajor;
    USHORT wServicePackMinor;
    USHORT wSuiteMask;
    UCHAR wProductType;
    UCHAR wReserved;
} RTL_OSVERSIONINFOEX, *PRTL_OSVERSIONINFOEX;

/* SuiteMask */
#define VER_WORKSTATION_NT                  0x40000000
#define VER_SERVER_NT                       0x80000000
#define VER_SUITE_SMALLBUSINESS             0x00000001
#define VER_SUITE_ENTERPRISE                0x00000002
#define VER_SUITE_BACKOFFICE                0x00000004
#define VER_SUITE_COMMUNICATIONS            0x00000008
#define VER_SUITE_TERMINAL                  0x00000010
#define VER_SUITE_SMALLBUSINESS_RESTRICTED  0x00000020
#define VER_SUITE_EMBEDDEDNT                0x00000040
#define VER_SUITE_DATACENTER                0x00000080
#define VER_SUITE_SINGLEUSERTS              0x00000100
#define VER_SUITE_PERSONAL                  0x00000200
#define VER_SUITE_BLADE                     0x00000400
#define VER_SUITE_EMBEDDED_RESTRICTED       0x00000800
#define VER_SUITE_SECURITY_APPLIANCE        0x00001000
#define VER_SUITE_STORAGE_SERVER            0x00002000
#define VER_SUITE_COMPUTE_SERVER            0x00004000
#define VER_SUITE_WH_SERVER                 0x00008000

/* Product types */
#define PRODUCT_UNDEFINED                           0x00000000
#define PRODUCT_ULTIMATE                            0x00000001
#define PRODUCT_HOME_BASIC                          0x00000002
#define PRODUCT_HOME_PREMIUM                        0x00000003
#define PRODUCT_ENTERPRISE                          0x00000004
#define PRODUCT_HOME_BASIC_N                        0x00000005
#define PRODUCT_BUSINESS                            0x00000006
#define PRODUCT_STANDARD_SERVER                     0x00000007
#define PRODUCT_DATACENTER_SERVER                   0x00000008
#define PRODUCT_SMALLBUSINESS_SERVER                0x00000009
#define PRODUCT_ENTERPRISE_SERVER                   0x0000000A
#define PRODUCT_STARTER                             0x0000000B
#define PRODUCT_DATACENTER_SERVER_CORE              0x0000000C
#define PRODUCT_STANDARD_SERVER_CORE                0x0000000D
#define PRODUCT_ENTERPRISE_SERVER_CORE              0x0000000E
#define PRODUCT_ENTERPRISE_SERVER_IA64              0x0000000F
#define PRODUCT_BUSINESS_N                          0x00000010
#define PRODUCT_WEB_SERVER                          0x00000011
#define PRODUCT_CLUSTER_SERVER                      0x00000012
#define PRODUCT_HOME_SERVER                         0x00000013
#define PRODUCT_STORAGE_EXPRESS_SERVER              0x00000014
#define PRODUCT_STORAGE_STANDARD_SERVER             0x00000015
#define PRODUCT_STORAGE_WORKGROUP_SERVER            0x00000016
#define PRODUCT_STORAGE_ENTERPRISE_SERVER           0x00000017
#define PRODUCT_SERVER_FOR_SMALLBUSINESS            0x00000018
#define PRODUCT_SMALLBUSINESS_SERVER_PREMIUM        0x00000019
#define PRODUCT_HOME_PREMIUM_N                      0x0000001A
#define PRODUCT_ENTERPRISE_N                        0x0000001B
#define PRODUCT_ULTIMATE_N                          0x0000001C
#define PRODUCT_WEB_SERVER_CORE                     0x0000001D
#define PRODUCT_MEDIUMBUSINESS_SERVER_MANAGEMENT    0x0000001E
#define PRODUCT_MEDIUMBUSINESS_SERVER_SECURITY      0x0000001F
#define PRODUCT_MEDIUMBUSINESS_SERVER_MESSAGING     0x00000020
#define PRODUCT_SERVER_FOUNDATION                   0x00000021
#define PRODUCT_HOME_PREMIUM_SERVER                 0x00000022
#define PRODUCT_SERVER_FOR_SMALLBUSINESS_V          0x00000023
#define PRODUCT_STANDARD_SERVER_V                   0x00000024
#define PRODUCT_DATACENTER_SERVER_V                 0x00000025
#define PRODUCT_ENTERPRISE_SERVER_V                 0x00000026
#define PRODUCT_DATACENTER_SERVER_CORE_V            0x00000027
#define PRODUCT_STANDARD_SERVER_CORE_V              0x00000028
#define PRODUCT_ENTERPRISE_SERVER_CORE_V            0x00000029
#define PRODUCT_HYPERV                              0x0000002A
#define PRODUCT_STORAGE_EXPRESS_SERVER_CORE         0x0000002B
#define PRODUCT_STORAGE_STANDARD_SERVER_CORE        0x0000002C
#define PRODUCT_STORAGE_WORKGROUP_SERVER_CORE       0x0000002D
#define PRODUCT_STORAGE_ENTERPRISE_SERVER_CORE      0x0000002E
#define PRODUCT_STARTER_N                           0x0000002F
#define PRODUCT_PROFESSIONAL                        0x00000030
#define PRODUCT_PROFESSIONAL_N                      0x00000031
#define PRODUCT_SB_SOLUTION_SERVER                  0x00000032
#define PRODUCT_SERVER_FOR_SB_SOLUTIONS             0x00000033
#define PRODUCT_STANDARD_SERVER_SOLUTIONS           0x00000034
#define PRODUCT_STANDARD_SERVER_SOLUTIONS_CORE      0x00000035
#define PRODUCT_SB_SOLUTION_SERVER_EM               0x00000036
#define PRODUCT_SERVER_FOR_SB_SOLUTIONS_EM          0x00000037
#define PRODUCT_SOLUTION_EMBEDDEDSERVER             0x00000038
#define PRODUCT_SOLUTION_EMBEDDEDSERVER_CORE        0x00000039
#define PRODUCT_ESSENTIALBUSINESS_SERVER_MGMT       0x0000003B
#define PRODUCT_ESSENTIALBUSINESS_SERVER_ADDL       0x0000003C
#define PRODUCT_ESSENTIALBUSINESS_SERVER_MGMTSVC    0x0000003D
#define PRODUCT_ESSENTIALBUSINESS_SERVER_ADDLSVC    0x0000003E
#define PRODUCT_SMALLBUSINESS_SERVER_PREMIUM_CORE   0x0000003F
#define PRODUCT_CLUSTER_SERVER_V                    0x00000040
#define PRODUCT_EMBEDDED                            0x00000041
#define PRODUCT_STARTER_E                           0x00000042
#define PRODUCT_HOME_BASIC_E                        0x00000043
#define PRODUCT_HOME_PREMIUM_E                      0x00000044
#define PRODUCT_PROFESSIONAL_E                      0x00000045
#define PRODUCT_ENTERPRISE_E                        0x00000046
#define PRODUCT_ULTIMATE_E                          0x00000047
#define PRODUCT_ENTERPRISE_EVALUATION               0x00000048
#define PRODUCT_MULTIPOINT_STANDARD_SERVER          0x0000004C
#define PRODUCT_MULTIPOINT_PREMIUM_SERVER           0x0000004D
#define PRODUCT_STANDARD_EVALUATION_SERVER          0x0000004F
#define PRODUCT_DATACENTER_EVALUATION_SERVER        0x00000050
#define PRODUCT_ENTERPRISE_N_EVALUATION             0x00000054
#define PRODUCT_EMBEDDED_AUTOMOTIVE                 0x00000055
#define PRODUCT_EMBEDDED_INDUSTRY_A                 0x00000056
#define PRODUCT_THINPC                              0x00000057
#define PRODUCT_EMBEDDED_A                          0x00000058
#define PRODUCT_EMBEDDED_INDUSTRY                   0x00000059
#define PRODUCT_EMBEDDED_E                          0x0000005A
#define PRODUCT_EMBEDDED_INDUSTRY_E                 0x0000005B
#define PRODUCT_EMBEDDED_INDUSTRY_A_E               0x0000005C
#define PRODUCT_STORAGE_WORKGROUP_EVALUATION_SERVER 0x0000005F
#define PRODUCT_STORAGE_STANDARD_EVALUATION_SERVER  0x00000060
#define PRODUCT_CORE_ARM                            0x00000061
#define PRODUCT_CORE_N                              0x00000062
#define PRODUCT_CORE_COUNTRYSPECIFIC                0x00000063
#define PRODUCT_CORE_SINGLELANGUAGE                 0x00000064
#define PRODUCT_CORE                                0x00000065
#define PRODUCT_PROFESSIONAL_WMC                    0x00000067
#define PRODUCT_ENTERPRISE_S_N_EVALUATION           0x00000082
#define PRODUCT_UNLICENSED                          0xABCDABCD

/* RtlVerifyVersionInfo() ComparisonType */

#define VER_EQUAL                       1
#define VER_GREATER                     2
#define VER_GREATER_EQUAL               3
#define VER_LESS                        4
#define VER_LESS_EQUAL                  5
#define VER_AND                         6
#define VER_OR                          7

#define VER_CONDITION_MASK              7
#define VER_NUM_BITS_PER_CONDITION_MASK 3

/* RtlVerifyVersionInfo() TypeMask */

#define VER_MINORVERSION                  0x0000001
#define VER_MAJORVERSION                  0x0000002
#define VER_BUILDNUMBER                   0x0000004
#define VER_PLATFORMID                    0x0000008
#define VER_SERVICEPACKMINOR              0x0000010
#define VER_SERVICEPACKMAJOR              0x0000020
#define VER_SUITENAME                     0x0000040
#define VER_PRODUCT_TYPE                  0x0000080

#define VER_NT_WORKSTATION              0x0000001
#define VER_NT_DOMAIN_CONTROLLER        0x0000002
#define VER_NT_SERVER                   0x0000003

#define VER_PLATFORM_WIN32s             0
#define VER_PLATFORM_WIN32_WINDOWS      1
#define VER_PLATFORM_WIN32_NT           2

#define VER_SET_CONDITION(ConditionMask, TypeBitMask, ComparisonType) \
  ((ConditionMask) = VerSetConditionMask((ConditionMask),             \
  (TypeBitMask), (ComparisonType)))

NTAPI NTSYSAPI ULONGLONG VerSetConditionMask(IN ULONGLONG ConditionMask,
					     IN ULONG TypeMask,
					     IN UCHAR Condition);

NTAPI NTSYSAPI NTSTATUS RtlGetVersion(OUT PRTL_OSVERSIONINFO lpVersionInformation);

NTAPI NTSYSAPI NTSTATUS RtlVerifyVersionInfo(IN PRTL_OSVERSIONINFOEX VersionInfo,
					     IN ULONG TypeMask,
					     IN ULONGLONG ConditionMask);
