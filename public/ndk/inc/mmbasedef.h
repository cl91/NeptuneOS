/* This file is imported by both the NT NDK and the Win32 SDK */

#pragma once

#include "ntbasedef.h"

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
 * Flags for ProcessExecutionOptions
 */
#define MEM_EXECUTE_OPTION_DISABLE                          0x1
#define MEM_EXECUTE_OPTION_ENABLE                           0x2
#define MEM_EXECUTE_OPTION_DISABLE_THUNK_EMULATION          0x4
#define MEM_EXECUTE_OPTION_PERMANENT                        0x8
#define MEM_EXECUTE_OPTION_EXECUTE_DISPATCH_ENABLE          0x10
#define MEM_EXECUTE_OPTION_IMAGE_DISPATCH_ENABLE            0x20
#define MEM_EXECUTE_OPTION_VALID_FLAGS                      0x3F

/*
 * Section Flags for NtCreateSection
 */
#define SEC_BASED		(0x00200000UL)
#define SEC_NO_CHANGE		(0x00400000UL)
#define SEC_FILE		(0x00800000UL)
#define SEC_IMAGE		(0x01000000UL)
#define SEC_RESERVE		(0x04000000UL)
#define SEC_COMMIT		(0x08000000UL)
#define SEC_NOCACHE		(0x10000000UL)
#define SEC_GLOBAL		(0x20000000UL)
#define SEC_LARGE_PAGES		(0x80000000UL)

/*
 * Virtual Memory Flags
 */
#define MEM_IMAGE                                           SEC_IMAGE
