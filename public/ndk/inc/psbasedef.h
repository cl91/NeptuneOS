/* This file is imported by both the NT NDK and the Win32 SDK */

#pragma once

#include "ntbasedef.h"

#define ALL_PROCESSOR_GROUPS 0xffff

/*
 * Process priority classes
 */
#define PROCESS_PRIORITY_CLASS_INVALID          0
#define PROCESS_PRIORITY_CLASS_IDLE             1
#define PROCESS_PRIORITY_CLASS_NORMAL           2
#define PROCESS_PRIORITY_CLASS_HIGH             3
#define PROCESS_PRIORITY_CLASS_REALTIME         4
#define PROCESS_PRIORITY_CLASS_BELOW_NORMAL     5
#define PROCESS_PRIORITY_CLASS_ABOVE_NORMAL     6

/*
 * Process base priorities
 */
#define PROCESS_PRIORITY_IDLE                   3
#define PROCESS_PRIORITY_NORMAL                 8
#define PROCESS_PRIORITY_NORMAL_FOREGROUND      9

/*
 * Process Access Types
 */
#define PROCESS_TERMINATE                       0x0001
#define PROCESS_CREATE_THREAD                   0x0002
#define PROCESS_SET_SESSIONID                   0x0004
#define PROCESS_VM_OPERATION                    0x0008
#define PROCESS_VM_READ                         0x0010
#define PROCESS_VM_WRITE                        0x0020
#define PROCESS_CREATE_PROCESS                  0x0080
#define PROCESS_SET_QUOTA                       0x0100
#define PROCESS_SET_INFORMATION                 0x0200
#define PROCESS_QUERY_INFORMATION               0x0400
#define PROCESS_SUSPEND_RESUME                  0x0800
#define PROCESS_QUERY_LIMITED_INFORMATION       0x1000
#define PROCESS_ALL_ACCESS                      (STANDARD_RIGHTS_REQUIRED | \
                                                 SYNCHRONIZE | \
                                                 0xFFFF)

typedef struct _QUOTA_LIMITS {
    SIZE_T PagedPoolLimit;
    SIZE_T NonPagedPoolLimit;
    SIZE_T MinimumWorkingSetSize;
    SIZE_T MaximumWorkingSetSize;
    SIZE_T PagefileLimit;
    LARGE_INTEGER TimeLimit;
} QUOTA_LIMITS, *PQUOTA_LIMITS;

typedef struct _IO_COUNTERS {
    ULONGLONG ReadOperationCount;
    ULONGLONG WriteOperationCount;
    ULONGLONG OtherOperationCount;
    ULONGLONG ReadTransferCount;
    ULONGLONG WriteTransferCount;
    ULONGLONG OtherTransferCount;
} IO_COUNTERS, *PIO_COUNTERS;

#define JOB_OBJECT_ASSIGN_PROCESS             0x0001
#define JOB_OBJECT_SET_ATTRIBUTES             0x0002
#define JOB_OBJECT_QUERY                      0x0004
#define JOB_OBJECT_TERMINATE                  0x0008
#define JOB_OBJECT_SET_SECURITY_ATTRIBUTES    0x0010
#define JOB_OBJECT_IMPERSONATE                0x0020
#define JOB_OBJECT_ALL_ACCESS                 (STANDARD_RIGHTS_REQUIRED | \
					       SYNCHRONIZE | 0x3F)

#define JOB_OBJECT_LIMIT_WORKINGSET           0x00000001
#define JOB_OBJECT_LIMIT_PROCESS_TIME         0x00000002
#define JOB_OBJECT_LIMIT_JOB_TIME             0x00000004
#define JOB_OBJECT_LIMIT_ACTIVE_PROCESS       0x00000008
#define JOB_OBJECT_LIMIT_AFFINITY             0x00000010
#define JOB_OBJECT_LIMIT_PRIORITY_CLASS       0x00000020
#define JOB_OBJECT_LIMIT_PRESERVE_JOB_TIME    0x00000040
#define JOB_OBJECT_LIMIT_SCHEDULING_CLASS     0x00000080
#define JOB_OBJECT_LIMIT_PROCESS_MEMORY       0x00000100
#define JOB_OBJECT_LIMIT_JOB_MEMORY           0x00000200
#define JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION 0x00000400
#define JOB_OBJECT_LIMIT_BREAKAWAY_OK         0x00000800
#define JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK  0x00001000
#define JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE    0x00002000

typedef struct _JOBOBJECT_BASIC_LIMIT_INFORMATION {
    LARGE_INTEGER PerProcessUserTimeLimit;
    LARGE_INTEGER PerJobUserTimeLimit;
    ULONG LimitFlags;
    SIZE_T MinimumWorkingSetSize;
    SIZE_T MaximumWorkingSetSize;
    ULONG ActiveProcessLimit;
    ULONG_PTR Affinity;
    ULONG PriorityClass;
    ULONG SchedulingClass;
} JOBOBJECT_BASIC_LIMIT_INFORMATION, *PJOBOBJECT_BASIC_LIMIT_INFORMATION;

typedef struct _JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
    JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
    IO_COUNTERS IoInfo;
    SIZE_T ProcessMemoryLimit;
    SIZE_T JobMemoryLimit;
    SIZE_T PeakProcessMemoryUsed;
    SIZE_T PeakJobMemoryUsed;
} JOBOBJECT_EXTENDED_LIMIT_INFORMATION, *PJOBOBJECT_EXTENDED_LIMIT_INFORMATION;

typedef enum _JOB_OBJECT_INFORMATION_CLASS {
    JobObjectBasicAccountingInformation = 1,
    JobObjectBasicLimitInformation,
    JobObjectBasicProcessIdList,
    JobObjectBasicUIRestrictions,
    JobObjectSecurityLimitInformation,
    JobObjectEndOfJobTimeInformation,
    JobObjectAssociateCompletionPortInformation,
    JobObjectBasicAndIoAccountingInformation,
    JobObjectExtendedLimitInformation,
    JobObjectJobSetInformation,
    MaxJobObjectInfoClass
} JOB_OBJECT_INFORMATION_CLASS, JOBOBJECTINFOCLASS;
