#pragma once

#include "../../ndk/inc/ntbasedef.h"
#include "../../ndk/inc/kebasedef.h"
#include "../../ndk/inc/rtlbasedef.h"
#include "../../ndk/inc/sebasedef.h"
#include "../../ndk/inc/psbasedef.h"
#include "../../ndk/inc/mmbasedef.h"
#include "../../ndk/inc/iobasedef.h"
#include "../../ndk/inc/exbasedef.h"
#include "../../ndk/inc/nls.h"
#include <winerror.h>

#define DECLSPEC_HIDDEN

#define INVALID_FILE_ATTRIBUTES    ((DWORD)-1)

typedef struct _TP_POOL TP_POOL, *PTP_POOL;
typedef struct _TP_WORK TP_WORK, *PTP_WORK;
typedef struct _TP_CALLBACK_INSTANCE TP_CALLBACK_INSTANCE, *PTP_CALLBACK_INSTANCE;
typedef struct _TP_TIMER TP_TIMER, *PTP_TIMER;
typedef struct _TP_WAIT TP_WAIT, *PTP_WAIT;
typedef struct _TP_IO TP_IO, *PTP_IO;

typedef DWORD TP_WAIT_RESULT;
typedef DWORD TP_VERSION, *PTP_VERSION;

typedef enum _TP_CALLBACK_PRIORITY {
    TP_CALLBACK_PRIORITY_HIGH,
    TP_CALLBACK_PRIORITY_NORMAL,
    TP_CALLBACK_PRIORITY_LOW,
    TP_CALLBACK_PRIORITY_INVALID,
    TP_CALLBACK_PRIORITY_COUNT = TP_CALLBACK_PRIORITY_INVALID
} TP_CALLBACK_PRIORITY;

typedef struct _TP_POOL_STACK_INFORMATION {
    SIZE_T StackReserve;
    SIZE_T StackCommit;
} TP_POOL_STACK_INFORMATION, *PTP_POOL_STACK_INFORMATION;

typedef VOID (NTAPI *PTP_WORK_CALLBACK)(_Inout_ PTP_CALLBACK_INSTANCE Instance,
					_Inout_opt_ PVOID Context,
					_Inout_ PTP_WORK Work);

typedef struct _TP_CLEANUP_GROUP TP_CLEANUP_GROUP, *PTP_CLEANUP_GROUP;

typedef VOID (NTAPI *PTP_SIMPLE_CALLBACK)(_Inout_ PTP_CALLBACK_INSTANCE Instance,
					  _Inout_opt_ PVOID Context);

typedef VOID (NTAPI *PTP_CLEANUP_GROUP_CANCEL_CALLBACK)(_Inout_opt_ PVOID ObjectContext,
							_Inout_opt_ PVOID CleanupContext);

typedef VOID (NTAPI *PTP_TIMER_CALLBACK)(PTP_CALLBACK_INSTANCE, PVOID, PTP_TIMER);
typedef VOID (NTAPI *PTP_WAIT_CALLBACK)(PTP_CALLBACK_INSTANCE, PVOID, PTP_WAIT, TP_WAIT_RESULT);

typedef struct _TP_CALLBACK_ENVIRON_V3 {
    TP_VERSION Version;
    PTP_POOL Pool;
    PTP_CLEANUP_GROUP CleanupGroup;
    PTP_CLEANUP_GROUP_CANCEL_CALLBACK CleanupGroupCancelCallback;
    PVOID RaceDll;
    struct _ACTIVATION_CONTEXT *ActivationContext;
    PTP_SIMPLE_CALLBACK FinalizationCallback;
    union {
	DWORD Flags;
	struct {
	    DWORD LongFunction : 1;
	    DWORD Persistent : 1;
	    DWORD Private : 30;
	} s;
    } u;
    TP_CALLBACK_PRIORITY CallbackPriority;
    DWORD Size;
} TP_CALLBACK_ENVIRON_V3, TP_CALLBACK_ENVIRON, *PTP_CALLBACK_ENVIRON;

typedef struct _OSVERSIONINFOA {
    DWORD dwOSVersionInfoSize;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwPlatformId;
    CHAR szCSDVersion[128];
} OSVERSIONINFOA, *POSVERSIONINFOA, *LPOSVERSIONINFOA;

typedef struct _OSVERSIONINFOEXA {
    DWORD dwOSVersionInfoSize;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwPlatformId;
    CHAR szCSDVersion[128];
    WORD wServicePackMajor;
    WORD wServicePackMinor;
    WORD wSuiteMask;
    BYTE wProductType;
    BYTE wReserved;
} OSVERSIONINFOEXA, *POSVERSIONINFOEXA, *LPOSVERSIONINFOEXA;
