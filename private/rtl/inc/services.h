#pragma once

#include <string.h>
#include <nt.h>
#include <gnu.h>
#include <compile_assert.h>
#include <sel4/sel4.h>

typedef seL4_Word MWORD;
#define MWORD_BYTES			(sizeof(MWORD))
#define MWORD_BITS			(MWORD_BYTES * 8)

#define PAGE_LOG2SIZE			(seL4_PageBits)
#define PAGE_ALIGN(p)			((MWORD)(p) & ~(PAGE_SIZE - 1))
#define PAGE_ALIGN_UP(p)		(PAGE_ALIGN((MWORD)(p) + PAGE_SIZE - 1))
#define IS_PAGE_ALIGNED(p)		(((MWORD)(p)) == PAGE_ALIGN(p))

/* The maximum number of zero bits (starting from the most significant bit) in
 * the virtual address that the user can specify in virtual memory allocation.
 * This is determined by the lowest user address, defined below */
#define MM_MAXIMUM_ZERO_BITS		(MWORD_BITS - PAGE_LOG2SIZE - 1)

/* All hard-coded addresses in client processes' address space go here. */
/* TODO: Use Windows/ReactOS address space scheme, especially KUSER_SHARED_DATA */
#define LOWEST_USER_ADDRESS		(1ULL << PAGE_LOG2SIZE)
/* First 1MB unmapped to catch stack overflow */
#define THREAD_STACK_START		(0x00100000ULL)
/* End of the address space where we can map user images */
#define USER_IMAGE_REGION_START		(0x00400000ULL)
#define USER_IMAGE_REGION_END		(0xb0000000ULL)
#define KUSER_SHARED_DATA_CLIENT_ADDR	(USER_SHARED_DATA)
#define WIN32_TEB_START			(USER_IMAGE_REGION_END)
#define WIN32_TEB_END			(0xbffdf000ULL)
#define WIN32_PEB_START			(WIN32_TEB_END)
/* Size of system dll tls region per thread is determined by the size
 * of the .tls section of the NTDLL.DLL image. */
#define SYSTEM_DLL_TLS_REGION_START	(0xc0010000ULL)
#define SYSTEM_DLL_TLS_REGION_END	(0xcff00000ULL)
/* 64K IPC buffer reserve per thread. 4K initial commit. */
#define IPC_BUFFER_START		(0xd0000000ULL)
#define IPC_BUFFER_END			(0xdfff0000ULL)
#define LOADER_SHARED_DATA_CLIENT_ADDR	IPC_BUFFER_END
#define USER_ADDRESS_END		(0xe0000000ULL)
#define HIGHEST_USER_ADDRESS		(USER_ADDRESS_END - 1)

#if KUSER_SHARED_DATA_CLIENT_ADDR >= USER_ADDRESS_END
#error "User shared data must be within user address space"
#endif

compile_assert(KUSER_SHARED_DATA_TOO_LARGE, USER_ADDRESS_END - LOADER_SHARED_DATA_CLIENT_ADDR >= PAGE_SIZE);

/*
 * We define a few custom NT status code, mainly to indicate
 * internal error or async state
 *
 * NTSTATUS Bits:
 * 0--15   Status code
 * 16--28  Facility
 * 29      Customer code flag
 * 30--31  Severity
 */

#define CUSTOMER_FLAG_BIT	29

#define FACILITY_ASYNC		0x43
#define FACILITY_SEL4		0x44
#define FACILITY_NTOS		0x45

#define ASYNC_SUCCESS(Code)	((NTSTATUS)(Code | (FACILITY_ASYNC << 16) \
					    | (1UL << CUSTOMER_FLAG_BIT) \
					    | ERROR_SEVERITY_SUCCESS))
#define ASYNC_INFORMATION(Code)	((NTSTATUS)(Code | (FACILITY_ASYNC << 16) \
					    | (1UL << CUSTOMER_FLAG_BIT) \
					    | ERROR_SEVERITY_INFORMATIONAL))
#define ASYNC_ERROR(Code)	((NTSTATUS)(Code | (FACILITY_ASYNC << 16) \
					    | (1UL << CUSTOMER_FLAG_BIT) \
					    | ERROR_SEVERITY_ERROR))
#define SEL4_ERROR(Code)	((NTSTATUS)(Code | (FACILITY_SEL4 << 16) \
					    | (1UL << CUSTOMER_FLAG_BIT) \
					    | ERROR_SEVERITY_ERROR))
#define NTOS_SUCCESS(Code)	((NTSTATUS)(Code | (FACILITY_NTOS << 16) \
					    | (1UL << CUSTOMER_FLAG_BIT) \
					    | ERROR_SEVERITY_SUCCESS))
#define NTOS_INFORMATION(Code)	((NTSTATUS)(Code | (FACILITY_NTOS << 16) \
					    | (1UL << CUSTOMER_FLAG_BIT) \
					    | ERROR_SEVERITY_INFORMATIONAL))
#define NTOS_ERROR(Code)	((NTSTATUS)(Code | (FACILITY_NTOS << 16) \
					    | (1UL << CUSTOMER_FLAG_BIT) \
					    | ERROR_SEVERITY_ERROR))

#define IS_ASYNC_STATUS(Code)			((((((ULONG)(Code)) >> 16) << 3) >> 3) == FACILITY_ASYNC)

#define STATUS_ASYNC_PENDING			ASYNC_INFORMATION(1)
#define STATUS_NTOS_BUG				NTOS_ERROR(1)
#define STATUS_NTOS_NO_REPLY			NTOS_INFORMATION(2)
#define STATUS_NTOS_INVOKE_OPEN_ROUTINE		NTOS_INFORMATION(3)

/*
 * Ipc buffer, where the seL4 IPC buffer is placed at the very beginning,
 * followed by the system service message buffer.
 */
#define IPC_BUFFER_RESERVE		(16 * PAGE_SIZE)
#define IPC_BUFFER_COMMIT		(PAGE_SIZE)
#define LOADER_SHARED_DATA_RESERVE	(USER_ADDRESS_END - LOADER_SHARED_DATA_CLIENT_ADDR)
#define LOADER_SHARED_DATA_COMMIT	(PAGE_SIZE)

/* Private heap reserved for the Ldr component of NTDLL */
#define NTDLL_LOADER_HEAP_RESERVE	(16 * PAGE_SIZE)
#define NTDLL_LOADER_HEAP_COMMIT	(4 * PAGE_SIZE)

typedef struct _NTDLL_THREAD_INIT_INFO {
    MWORD SystemServiceCap;
    MWORD WdmServiceCap;
    CONTEXT InitialContext;
} NTDLL_THREAD_INIT_INFO, *PNTDLL_THREAD_INIT_INFO;

typedef struct _NTDLL_DRIVER_INIT_INFO {
    MWORD IncomingIoPacketBuffer;
    MWORD OutgoingIoPacketBuffer;
    MWORD InitialCoroutineStackTop;
    MWORD X86TscFreq;
} NTDLL_DRIVER_INIT_INFO, *PNTDLL_DRIVER_INIT_INFO;

typedef struct _NTDLL_PROCESS_INIT_INFO {
    MWORD LoaderHeapStart;
    MWORD ProcessHeapStart;
    MWORD ProcessHeapReserve;
    MWORD ProcessHeapCommit;
    HANDLE CriticalSectionLockSemaphore;
    HANDLE LoaderLockSemaphore;
    HANDLE FastPebLockSemaphore;
    HANDLE ProcessHeapListLockSemaphore;
    HANDLE VectoredHandlerLockSemaphore;
    HANDLE ProcessHeapLockSemaphore;
    HANDLE LoaderHeapLockSemaphore;
    BOOLEAN DriverProcess;
    NTDLL_DRIVER_INIT_INFO DriverInitInfo;
    NTDLL_THREAD_INIT_INFO ThreadInitInfo;
} NTDLL_PROCESS_INIT_INFO, *PNTDLL_PROCESS_INIT_INFO;

/*
 * Entrypoint routine of wdm.dll. In driver processes we don't call the
 * driver entry point directly, and instead call WdmStartup. */
typedef VOID (*PWDM_DLL_ENTRYPOINT)(IN seL4_IPCBuffer *IpcBuffer,
				    IN seL4_CPtr WdmServiceCap,
				    IN PNTDLL_DRIVER_INIT_INFO InitInfo,
				    IN PUNICODE_STRING DriverRegistryPath);

/*
 * System dll TLS index. Executable has TLS index == 0. NTDLL always
 * has TLS index == 1.
 */
#define SYSTEMDLL_TLS_INDEX	1

/*
 * Shared data structure between the NTOS server and the NTDLL loader
 * component. The layout is
 * [LDRP_LOADED_MODULE] [DllPath] [DllName]
 * ------------- EntrySize ----------------
 * Note: All offsets are with respect to LOADER_SHARED_DATA_CLIENT_ADDR
 */
typedef struct _LDRP_LOADED_MODULE {
    MWORD DllPath;     /* Offset to the full path of the dll file */
    MWORD DllName;     /* Offset to the dllname (eg kernel32.dll) */
    MWORD ViewBase;    /* Client address at which the dll is loaded */
    MWORD ViewSize;    /* Total size of the virtual memory of the image */
    MWORD EntrySize;   /* Size of this struct plus the strings */
} LDRP_LOADED_MODULE, *PLDRP_LOADED_MODULE;

/*
 * Per-process equivalent of KUSER_SHARED_DATA. This has the same function
 * as Win32 PEB, except that we don't expose it to the public headers.
 *
 * Note: All offsets are with respect to LOADER_SHARED_DATA_CLIENT_ADDR
 */
typedef struct _LOADER_SHARED_DATA {
    MWORD LoadedModuleCount;
    MWORD ImagePath; /* Offset to the full path of the image file */
    MWORD ImageName; /* Offset to the base name of image (eg smss.exe) */
    MWORD CommandLine; /* For user processes, this is the command line.
			* For drivers, this is the driver service registry key */
    MWORD LoadedModules; /* Offset to the start of loaded module entries */
} LOADER_SHARED_DATA, *PLOADER_SHARED_DATA;

#if seL4_PageBits <= seL4_IPCBufferSizeBits
#error "seL4 IPC Buffer too large (must be no larger than half of a 4K page)"
#endif

/* Service message buffer sits immediately after the seL4 IPC buffer */
#define SEL4_IPC_BUFFER_SIZE	(1UL << seL4_IPCBufferSizeBits)
#define SVC_MSGBUF_SIZE		((1UL << seL4_PageBits) - SEL4_IPC_BUFFER_SIZE)

/*
 * Points to a buffer (within the service message buffer) which stores
 * an argument to the service. The client stub copies the client data
 * into the buffer and passes the pointer to the server.
 */
typedef union _SERVICE_ARGUMENT {
    struct {
	USHORT BufferStart; /* Relative to the beginning of svc msg buffer */
	USHORT BufferSize;
    };
    MWORD Word;
} SERVICE_ARGUMENT;

assert_size_correct(SERVICE_ARGUMENT, MWORD_BYTES);

static inline BOOLEAN KiServiceValidateArgument(IN MWORD MsgWord)
{
    SERVICE_ARGUMENT Arg = { .Word = MsgWord };
    if (((ULONG)(Arg.BufferStart) + Arg.BufferSize) > SVC_MSGBUF_SIZE) {
	return FALSE;
    }
    return TRUE;
}

#define SVC_MSGBUF_OFFSET_TO_ARG(IpcBufAddr, Offset, Type) (*((Type *)(IpcBufAddr + SEL4_IPC_BUFFER_SIZE + (Offset))))

static inline PVOID KiServiceGetArgument(IN MWORD IpcBufferAddr,
					 IN MWORD MsgWord)
{
    if (MsgWord == 0) {
	return NULL;
    }
    SERVICE_ARGUMENT Arg = { .Word = MsgWord };
    return &SVC_MSGBUF_OFFSET_TO_ARG(IpcBufferAddr, Arg.BufferStart, VOID);
}

static inline NTSTATUS KiServiceMarshalArgument(IN MWORD IpcBufferAddr,
						IN OUT ULONG *MsgBufOffset,
						IN PVOID Argument,
						IN MWORD ArgSize,
						OUT SERVICE_ARGUMENT *SvcArg)
{
    if (*MsgBufOffset > SVC_MSGBUF_SIZE) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    if (SVC_MSGBUF_SIZE - *MsgBufOffset < ArgSize) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    memcpy(&SVC_MSGBUF_OFFSET_TO_ARG(IpcBufferAddr, *MsgBufOffset, VOID), Argument, ArgSize);
    SvcArg->BufferStart = *MsgBufOffset;
    SvcArg->BufferSize = ArgSize;
    *MsgBufOffset += ArgSize;
    return STATUS_SUCCESS;
}

/*
 * APC Routine
 */
typedef VOID (NTAPI *PKAPC_ROUTINE)(IN PVOID SystemArgument1,
				    IN PVOID SystemArgument2,
				    IN PVOID SystemArgument3);

/*
 * APC object that is passed by the service handlers
 */
typedef struct _APC_OBJECT {
    PKAPC_ROUTINE ApcRoutine;
    PVOID ApcContext[3];
} APC_OBJECT, *PAPC_OBJECT;

#define MAX_APC_COUNT_PER_DELIVERY	16

/*
 * We use a SHORT to indicate the number of APCs being delivered.
 * Therefore the number of APCs per delivery is limited.
 * In practice, since on the client side the APC object is being
 * passed on the stack the maximum number of APCs per delivery
 * should not be larger than 32, otherwise stack overflow might occur.
 */
#if MAX_APC_COUNT_PER_DELIVERY >= 32767
#error "Too many ACPs per delivery"
#endif

#include <syssvc_gen.h>

compile_assert(TOO_MANY_SYSTEM_SERVICES, NUMBER_OF_SYSTEM_SERVICES < 0x1000UL);
