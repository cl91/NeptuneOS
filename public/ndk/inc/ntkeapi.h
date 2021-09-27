#pragma once

typedef LONG KPRIORITY;
typedef ULONG_PTR KAFFINITY;

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
 * Shared Kernel User Data
 *
 * Note that this data structure is different from its ReactOS
 * or Windows counterpart, since we cannot actually map the
 * kernel shared user data at the desired place (0xFFDF0000 in
 * i386 or 0xFFFFF780`00000000 in amd64). Therefore we might as
 * well make them incompatible. Portable code shouldn't depend
 * on it anyway.
 */
typedef struct _KUSER_SHARED_DATA {
    volatile KSYSTEM_TIME SystemTime;
    volatile KSYSTEM_TIME TickCount;
    ULONG_PTR Cookie;
    ULONG TickCountMultiplier;
    BOOLEAN ProcessorFeatures[PROCESSOR_FEATURE_MAX];
} KUSER_SHARED_DATA, *PKUSER_SHARED_DATA;

typedef struct DECLSPEC_ALIGN(16) _M128A {
    ULONGLONG Low;
    LONGLONG High;
} M128A, *PM128A;

typedef struct DECLSPEC_ALIGN(16) _XSAVE_FORMAT {
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
} XSAVE_FORMAT, *PXSAVE_FORMAT;

#ifdef _M_IX86
#include <nti386.h>
#endif

#ifdef _M_AMD64
#include <ntamd64.h>
#endif

/*
 * Native Calls. These are only available for client threads.
 * The NTOS root task has different function signatures for these.
 */
#ifndef _NTOSKRNL_

NTAPI NTSYSAPI NTSTATUS NtContinue(IN PCONTEXT Context,
				   IN BOOLEAN TestAlert);

NTAPI NTSYSAPI ULONG NtGetCurrentProcessorNumber(VOID);

#endif
