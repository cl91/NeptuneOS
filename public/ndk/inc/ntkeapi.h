#pragma once

#include "ntdef.h"
#include "ntstatus.h"
#include "nls.h"

//
// Processor Architectures
//
#define PROCESSOR_ARCHITECTURE_INTEL    0
#define PROCESSOR_ARCHITECTURE_MIPS     1
#define PROCESSOR_ARCHITECTURE_ALPHA    2
#define PROCESSOR_ARCHITECTURE_PPC      3
#define PROCESSOR_ARCHITECTURE_SHX      4
#define PROCESSOR_ARCHITECTURE_ARM      5
#define PROCESSOR_ARCHITECTURE_IA64     6
#define PROCESSOR_ARCHITECTURE_ALPHA64  7
#define PROCESSOR_ARCHITECTURE_MSIL     8
#define PROCESSOR_ARCHITECTURE_AMD64    9
#define PROCESSOR_ARCHITECTURE_UNKNOWN  0xFFFF

typedef LONG KPRIORITY;
typedef ULONG_PTR KAFFINITY;

typedef enum _KWAIT_REASON {
    Executive,
    FreePage,
    PageIn,
    PoolAllocation,
    DelayExecution,
    Suspended,
    UserRequest,
    WrExecutive,
    WrFreePage,
    WrPageIn,
    WrPoolAllocation,
    WrDelayExecution,
    WrSuspended,
    WrUserRequest,
    WrEventPair,
    WrQueue,
    WrLpcReceive,
    WrLpcReply,
    WrVirtualMemory,
    WrPageOut,
    WrRendezvous,
    WrKeyedEvent,
    WrTerminated,
    WrProcessInSwap,
    WrCpuRateControl,
    WrCalloutStack,
    WrKernel,
    WrResource,
    WrPushLock,
    WrMutex,
    WrQuantumEnd,
    WrDispatchInt,
    WrPreempted,
    WrYieldExecution,
    WrFastMutex,
    WrGuardedMutex,
    WrRundown,
    MaximumWaitReason
} KWAIT_REASON;

/*
 * System Time Structure
 */
typedef struct _KSYSTEM_TIME {
    ULONG LowPart;
    LONG High1Time;
    LONG High2Time;
} KSYSTEM_TIME, *PKSYSTEM_TIME;

/*
 * Processor features
 */
#define PF_FLOATING_POINT_PRECISION_ERRATA       0
#define PF_FLOATING_POINT_EMULATED               1
#define PF_COMPARE_EXCHANGE_DOUBLE               2
#define PF_MMX_INSTRUCTIONS_AVAILABLE            3
#define PF_PPC_MOVEMEM_64BIT_OK                  4
#define PF_ALPHA_BYTE_INSTRUCTIONS               5
#define PF_XMMI_INSTRUCTIONS_AVAILABLE           6
#define PF_3DNOW_INSTRUCTIONS_AVAILABLE          7
#define PF_RDTSC_INSTRUCTION_AVAILABLE           8
#define PF_PAE_ENABLED                           9
#define PF_XMMI64_INSTRUCTIONS_AVAILABLE        10
#define PF_SSE_DAZ_MODE_AVAILABLE               11
#define PF_NX_ENABLED                           12
#define PF_SSE3_INSTRUCTIONS_AVAILABLE          13
#define PF_COMPARE_EXCHANGE128                  14
#define PF_COMPARE64_EXCHANGE128                15
#define PF_CHANNELS_ENABLED                     16
#define PF_XSAVE_ENABLED                        17
#define PF_ARM_VFP_32_REGISTERS_AVAILABLE       18
#define PF_ARM_NEON_INSTRUCTIONS_AVAILABLE      19
#define PF_SECOND_LEVEL_ADDRESS_TRANSLATION     20
#define PF_VIRT_FIRMWARE_ENABLED                21
#define PF_RDWRFSGSBASE_AVAILABLE               22
#define PF_FASTFAIL_AVAILABLE                   23
#define PF_ARM_DIVIDE_INSTRUCTION_AVAILABLE     24
#define PF_ARM_64BIT_LOADSTORE_ATOMIC           25
#define PF_ARM_EXTERNAL_CACHE_AVAILABLE         26
#define PF_ARM_FMAC_INSTRUCTIONS_AVAILABLE      27
#define PF_RDRAND_INSTRUCTION_AVAILABLE         28
#define PF_ARM_V8_INSTRUCTIONS_AVAILABLE        29
#define PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE 30
#define PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE  31

#define PROCESSOR_FEATURE_MAX 64

/*
 * NT Product and Architecture Types
 */
typedef enum _NT_PRODUCT_TYPE {
    NtProductWinNt = 1,
    NtProductLanManNt,
    NtProductServer
} NT_PRODUCT_TYPE, *PNT_PRODUCT_TYPE;

typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE {
    StandardDesign,
    NEC98x86,
    EndAlternatives
} ALTERNATIVE_ARCHITECTURE_TYPE;

/*
 * Shared Kernel User Data
 *
 * This is exposed to user land (for both i386 and amd64 it is at 0x7ffe0000)
 * so we must maintain compatibility with Windows/ReactOS.
 */
#include <pshpack4.h>
typedef struct _KUSER_SHARED_DATA {
    ULONG TickCountLowDeprecated;
    ULONG TickCountMultiplier;
    volatile KSYSTEM_TIME InterruptTime;
    volatile KSYSTEM_TIME SystemTime;
    volatile KSYSTEM_TIME TimeZoneBias;
    USHORT ImageNumberLow;
    USHORT ImageNumberHigh;
    WCHAR NtSystemRoot[260];
    ULONG MaxStackTraceDepth;
    ULONG CryptoExponent;
    ULONG TimeZoneId;
    ULONG LargePageMinimum;
    ULONG Reserved2[7];
    NT_PRODUCT_TYPE NtProductType;
    BOOLEAN ProductTypeIsValid;
    ULONG NtMajorVersion;
    ULONG NtMinorVersion;
    BOOLEAN ProcessorFeatures[PROCESSOR_FEATURE_MAX];
    ULONG Reserved1;
    ULONG Reserved3;
    volatile ULONG TimeSlip;
    ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;
    ULONG AltArchitecturePad[1];
    LARGE_INTEGER SystemExpirationDate;
    ULONG SuiteMask;
    BOOLEAN KdDebuggerEnabled;
    UCHAR NXSupportPolicy;
    volatile ULONG ActiveConsoleId;
    volatile ULONG DismountCount;
    ULONG ComPlusPackage;
    ULONG LastSystemRITEventTickCount;
    ULONG NumberOfPhysicalPages;
    BOOLEAN SafeBootMode;
    union {
	UCHAR TscQpcData;
	struct {
	    UCHAR TscQpcEnabled:1;
	    UCHAR TscQpcSpareFlag:1;
	    UCHAR TscQpcShift:6;
	};
    };
    UCHAR TscQpcPad[2];
    union {
	ULONG SharedDataFlags;
	struct {
	    ULONG DbgErrorPortPresent:1;
	    ULONG DbgElevationEnabled:1;
	    ULONG DbgVirtEnabled:1;
	    ULONG DbgInstallerDetectEnabled:1;
	    ULONG DbgSystemDllRelocated:1;
	    ULONG DbgDynProcessorEnabled:1;
	    ULONG DbgSEHValidationEnabled:1;
	    ULONG SpareBits:25;
	};
	ULONG TraceLogging;
    };
    ULONG DataFlagsPad[1];
    ULONGLONG TestRetInstruction;
    ULONG SystemCall;
    ULONG SystemCallReturn;
    ULONGLONG SystemCallPad[3];
    union {
	volatile KSYSTEM_TIME TickCount;
	volatile ULONG64 TickCountQuad;
	struct {
	    ULONG ReservedTickCountOverlay[3];
	    ULONG TickCountPad[1];
	};
    };
    ULONG Cookie;
    ULONG CookiePad[1];
    LCID DefaultLocale;
} KUSER_SHARED_DATA, *PKUSER_SHARED_DATA;
#include <poppack.h>

#if defined(_M_IX86) || defined(_M_AMD64)
typedef struct DECLSPEC_ALIGN(16) _M128A {
    ULONGLONG Low;
    LONGLONG High;
} M128A, *PM128A;

typedef struct DECLSPEC_ALIGN(16) _XMM_SAVE_AREA32 {
    USHORT ControlWord;
    USHORT StatusWord;
    UCHAR TagWord;
    UCHAR Reserved1;
    USHORT ErrorOpcode;
    ULONG ErrorOffset;
    USHORT ErrorSelector;
    USHORT Reserved2;
    ULONG DataOffset;
    USHORT DataSelector;
    USHORT Reserved3;
    ULONG MxCsr;
    ULONG MxCsr_Mask;
    M128A FloatRegisters[8];
#if defined(_WIN64)
    M128A XmmRegisters[16];
    UCHAR Reserved4[96];
#else
    M128A XmmRegisters[8];
    UCHAR Reserved4[192];
    ULONG StackControl[7];
    ULONG Cr0NpxState;
#endif
} XMM_SAVE_AREA32, *PXMM_SAVE_AREA32;
#endif

#ifdef _M_IX86
#include <nti386.h>
#endif

#ifdef _M_AMD64
#include <ntamd64.h>
#endif

#ifdef _M_ARM64
#include <ntarm64.h>
#endif

FORCEINLINE KAFFINITY AFFINITY_MASK(ULONG Index)
{
    return (KAFFINITY)1 << Index;
}

/*
 * Native Calls. These are only available for client threads.
 * The NTOS root task has different function signatures for these.
 */
#ifndef _NTOSKRNL_

NTAPI NTSYSAPI NTSTATUS NtContinue(IN PCONTEXT Context,
				   IN BOOLEAN TestAlert);

NTAPI NTSYSAPI NTSTATUS NtTestAlert(VOID);

NTAPI NTSYSAPI NTSTATUS NtDelayExecution(IN BOOLEAN Alertable,
					 IN LARGE_INTEGER *Interval);

NTAPI NTSYSAPI ULONG NtGetCurrentProcessorNumber(VOID);

NTAPI NTSYSAPI NTSTATUS NtQuerySystemTime(OUT PLARGE_INTEGER CurrentTime);

#endif
