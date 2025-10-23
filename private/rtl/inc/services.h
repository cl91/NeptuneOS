#pragma once

#include <string.h>
#include <nt.h>
#include <gnu.h>
#include <compile_assert.h>
#include "private_ntstatus.h"

/*
 * For each thread we reserve four pages in the address space of its
 * process and and place the IPC buffer page at the very beginning,
 * followed by one unmapped page and then the NT thread environment
 * block. The last page is unmapped. The unmapped pages are intended
 * to catch buffer overflows and underflows.
 */
#define IPC_BUFFER_RESERVE		(2 * PAGE_SIZE)
#define IPC_BUFFER_COMMIT		(PAGE_SIZE)
#define NT_TIB_OFFSET			(IPC_BUFFER_RESERVE)
#define NT_TIB_RESERVE			(2 * PAGE_SIZE)
#define NT_TIB_COMMIT			(PAGE_SIZE)

#include <sel4/sel4.h>

typedef seL4_Word MWORD;
#define MWORD_BYTES			(sizeof(MWORD))
#define MWORD_BITS			(MWORD_BYTES * 8)

#define PAGE_LOG2SIZE			(seL4_PageBits)
#define LARGE_PAGE_LOG2SIZE		(seL4_LargePageBits)
#define LARGE_PAGE_SIZE			(1ULL << LARGE_PAGE_LOG2SIZE)
#define PAGE_ALIGN(p)			((MWORD)(p) & ~(PAGE_SIZE - 1))
#define PAGE_ALIGN_UP(p)		(PAGE_ALIGN((MWORD)(p) + PAGE_SIZE - 1))
#define IS_PAGE_ALIGNED(p)		(((MWORD)(p)) == PAGE_ALIGN(p))
#define ALIGN_DOWN_64(n, align)		(((ULONGLONG)(n)) & ~((align) - 1LL))
#define ALIGN_UP_64(n, align)		ALIGN_DOWN_64(((ULONGLONG)(n))+(align)-1LL, (align))
#define PAGE_ALIGN64(p)			ALIGN_DOWN_64(p, PAGE_SIZE)
#define PAGE_ALIGN_UP64(p)		ALIGN_UP_64(p, PAGE_SIZE)
#define IS_PAGE_ALIGNED64(p)		(PAGE_ALIGN64(p) == (ULONG64)(p))
#define IS_ALIGNED_BY(addr, align)	((ULONG_PTR)(addr) == ALIGN_DOWN_BY(addr, align))
#define IS_ALIGNED(addr, type)		((ULONG_PTR)(addr) == ALIGN_DOWN(addr, type))

/* The maximum number of zero bits (starting from the most significant bit) in
 * the virtual address that the user can specify in virtual memory allocation.
 * This is determined by the lowest user address, defined below */
#define MM_MAXIMUM_ZERO_HIGH_BITS	(MWORD_BITS - PAGE_LOG2SIZE - 1)

#ifdef _WIN64
#define MWORD_LOG2SIZE			(3)
#define ADDRSPACE_SHIFT			(16)
#else
#define MWORD_LOG2SIZE			(2)
#define ADDRSPACE_SHIFT			(0)
#endif

#define MWORD_BITS_LOG2SIZE		(MWORD_LOG2SIZE + 3)

/* All hard-coded addresses in client processes' address space go here. */
#define LOWEST_USER_ADDRESS		(1ULL << PAGE_LOG2SIZE)
/* First 1MB unmapped to catch stack overflow */
#define THREAD_STACK_START		(0x00100000ULL)
/* Start of the address space where we can map user images */
#define USER_IMAGE_REGION_START		(0x00400000ULL)

#ifndef _WIN64
/* On 32-bit architectures we generally follow the Windows address space
 * organization with /3GB enabled. USER_ADDRESS_END is the end of client-
 * manageable user space. The address space between USER_ADDRESS_END and
 * seL4_UserTop is reserved for private data structures that the NTOS
 * server maps into client address space.*/
#define USER_ADDRESS_END		(0xc0000000ULL)
#define IPC_BUFFER_START		(0xc0010000ULL)
#define IPC_BUFFER_END			(0xdfff0000ULL)
#else
#define USER_ADDRESS_END		(0x700000000000ULL)
#define IPC_BUFFER_START		(0x700000010000ULL)
#define IPC_BUFFER_END			(0x7fffffff0000ULL)
#endif	/* _WIN64 */

#define KUSER_SHARED_DATA_CLIENT_ADDR	(USER_SHARED_DATA)
#define HIGHEST_USER_ADDRESS		(USER_ADDRESS_END - 1)

/*
 * IPC buffer cannot exceed 64KB because we use a SHORT to represent
 * the buffer argument offset and size. On 64-bit architectures this can
 * potentially be enlarged but I don't see the point of having more than
 * a 64KB IPC buffer.
 */
#if IPC_BUFFER_RESERVE > 0x10000
#error "IPC buffer too large"
#endif

/*
 * Maximum amount of data we can pass in the IRP itself. If user buffer
 * exceeds this size, we will directly map user buffer into server or
 * driver address space. This cannot exceed the service message buffer
 * size, and should be reasonably small (but not too small), such that
 * the overhead of mapping and unmapping exceeds the overhead of copy.
 * Additionally, since the data in the service message buffer are
 * transient, to simply the IRP handling logic for device objects with
 * DIRECT_IO as the IO transfer type, this value cannot be larger than
 * the typical sector size (512 bytes).
 */
#define IRP_DATA_BUFFER_SIZE	(512)

/* Each client thread gets its own private CSpace, with the zeroth slot pointing
 * to the shared CNode for its process. We don't neeed a huge CNode for either
 * the private or the shared CNode, since we only use client-side cap slots for
 * IPC endpoints. Even the most heavy RPC services rarely need more than 20 LPC
 * connections per thread. Note the process shared CNode size is slightly larger
 * so drivers which access a lot of X86 ports can have enough cap slots there. */
#define PROCESS_SHARED_CNODE_LOG2SIZE	(MWORD_BITS_LOG2SIZE + 1)
#define THREAD_PRIVATE_CNODE_LOG2SIZE	(MWORD_BITS_LOG2SIZE)

/* Private heap reserved for the Ldr component of NTDLL */
#define NTDLL_LOADER_HEAP_RESERVE	(16 * PAGE_SIZE)
#define NTDLL_LOADER_HEAP_COMMIT	(4 * PAGE_SIZE)

#ifdef _M_IX86
#define RETURN_VALUE		Eax
#define INSTRUCTION_POINTER	Eip
#define STACK_POINTER		Esp
#define FASTCALL_FIRST_PARAM	Ecx
#define FASTCALL_SECOND_PARAM	Edx
#define _INSTRUCTION_POINTER	eip
#define _STACK_POINTER		esp
#define _FASTCALL_FIRST_PARAM	ecx
#define _FASTCALL_SECOND_PARAM	edx
#elif defined(_M_AMD64)
#define RETURN_VALUE		Rax
#define INSTRUCTION_POINTER	Rip
#define STACK_POINTER		Rsp
#define FASTCALL_FIRST_PARAM	Rcx
#define FASTCALL_SECOND_PARAM	Rdx
#define _INSTRUCTION_POINTER	rip
#define _STACK_POINTER		rsp
#define _FASTCALL_FIRST_PARAM	rcx
#define _FASTCALL_SECOND_PARAM	rdx
#elif defined(_M_ARM64)
#define RETURN_VALUE		X0
#define INSTRUCTION_POINTER	Pc
#define STACK_POINTER		Sp
#define FASTCALL_FIRST_PARAM	X0
#define FASTCALL_SECOND_PARAM	X1
#define _INSTRUCTION_POINTER	pc
#define _STACK_POINTER		sp
#define _FASTCALL_FIRST_PARAM	x0
#define _FASTCALL_SECOND_PARAM	x1
#else
#error "Unsupported architecture"
#endif

/* This is used to distinguish VM faults from user exceptions. See ntos/ke/services.c */
#define KI_VM_FAULT_CODE	(0xFFFF)

static inline VOID KeSetThreadContextFromEntryPoint(OUT PCONTEXT Context,
						    IN PTHREAD_START_ROUTINE EntryPoint,
						    IN PVOID Parameter)
{
    Context->INSTRUCTION_POINTER = (ULONG_PTR)EntryPoint;
    Context->FASTCALL_FIRST_PARAM = (ULONG_PTR)Parameter;
}

static inline VOID KeGetEntryPointFromThreadContext(IN PCONTEXT Context,
						    OUT PTHREAD_START_ROUTINE *EntryPoint,
						    OUT PVOID *Parameter)
{
    *EntryPoint = (PVOID)Context->INSTRUCTION_POINTER;
    *Parameter = (PVOID)Context->FASTCALL_FIRST_PARAM;
}

/* This is the thread context as defined by seL4, which contains mostly
 * integer registers and a small number of control registers. Not to be
 * confused with the full CONTEXT, defined in the NT headers. */
typedef seL4_UserContext THREAD_CONTEXT, *PTHREAD_CONTEXT;

typedef struct _NTDLL_THREAD_INIT_INFO {
    MWORD SystemServiceCap;
    MWORD WdmServiceCap;
    MWORD StackTop;
    MWORD StackReserve;
    CLIENT_ID ClientId;
    CONTEXT Context;
} NTDLL_THREAD_INIT_INFO, *PNTDLL_THREAD_INIT_INFO;

#define INIT_INFO_NTDLL_PATH_SIZE	(32)
#define INIT_INFO_IMAGE_NAME_SIZE	(512)
#define INIT_INFO_SERVICE_PATH_SIZE	(512)

typedef struct _NTDLL_DRIVER_INIT_INFO {
    MWORD IncomingIoPacketBuffer;
    MWORD OutgoingIoPacketBuffer;
    MWORD InitialCoroutineStackTop;
    MWORD X86TscFreq;
    MWORD DpcMutexCap;
    MWORD WorkItemMutexCap;
    CHAR ServicePath[INIT_INFO_SERVICE_PATH_SIZE]; /* Driver service registry key */
} NTDLL_DRIVER_INIT_INFO, *PNTDLL_DRIVER_INIT_INFO;

typedef struct _NTDLL_PROCESS_INIT_INFO {
    MWORD ImageBase;
    MWORD PebAddress;
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
    MWORD NtdllViewBase; /* Client address at which ntdll is loaded */
    MWORD NtdllViewSize; /* Total virtual memory size of the ntdll image */
    CHAR NtdllPath[INIT_INFO_NTDLL_PATH_SIZE]; /* Full path of the ntdll image */
    CHAR ImageName[INIT_INFO_IMAGE_NAME_SIZE]; /* Base name of the image (eg smss.exe) */
    union {
	BOOLEAN DriverProcess;
	MWORD Padding;
    };
    NTDLL_DRIVER_INIT_INFO DriverInitInfo;
    NTDLL_THREAD_INIT_INFO ThreadInitInfo;
} NTDLL_PROCESS_INIT_INFO, *PNTDLL_PROCESS_INIT_INFO;

compile_assert(INIT_INFO_TOO_BIG, sizeof(NTDLL_PROCESS_INIT_INFO) < PAGE_SIZE);

/*
 * Entrypoint routine of wdm.dll. In driver processes we don't call the
 * driver entry point directly, and instead call WdmStartup. */
typedef VOID (*PWDM_DLL_ENTRYPOINT)(IN seL4_CPtr WdmServiceCap,
				    IN PNTDLL_DRIVER_INIT_INFO InitInfo,
				    IN PUNICODE_STRING DriverRegistryPath);

#if seL4_PageBits <= seL4_IPCBufferSizeBits
#error "seL4 IPC Buffer too large (must be no larger than half of a 4K page)"
#endif

/* Service message buffer sits immediately after the seL4 IPC buffer */
#define SEL4_IPC_BUFFER_SIZE	(1UL << seL4_IPCBufferSizeBits)
#define SVC_MSGBUF_SIZE		(IPC_BUFFER_COMMIT - SEL4_IPC_BUFFER_SIZE)
/* Alignment of the data structures passed via the service message buffer */
#define SVC_MSGBUF_ALIGN	(16)

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

#define SVC_MSGBUF_OFFSET_TO_ARG(IpcBufAddr, Offset, Type)		\
    (*((Type *)((ULONG_PTR)(IpcBufAddr) + SEL4_IPC_BUFFER_SIZE + (Offset))))

static inline PVOID KiServiceGetArgument(IN MWORD IpcBufferAddr,
					 IN MWORD MsgWord)
{
    if (MsgWord == 0) {
	return NULL;
    }
    SERVICE_ARGUMENT Arg = { .Word = MsgWord };
    return &SVC_MSGBUF_OFFSET_TO_ARG(IpcBufferAddr, Arg.BufferStart, CHAR);
}

/*
 * APC Routine
 */
typedef VOID (NTAPI *PKAPC_ROUTINE)(IN PVOID SystemArgument1,
				    IN PVOID SystemArgument2,
				    IN PVOID SystemArgument3);

/*
 * APC Type
 */
#define APC_TYPE_KAPC	0
#define APC_TYPE_IO	1

/*
 * APC object that is passed by the service handlers
 */
typedef struct _APC_OBJECT {
    MWORD ApcType;
    PKAPC_ROUTINE ApcRoutine;
    PVOID ApcContext[6];
} APC_OBJECT, *PAPC_OBJECT;

#define MAX_APC_PER_DELIVERY	16

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

/*
 * For the NT LPC communication port handle, the second lowest bit is set
 * to distinguish it from regular NT handles. These special handles are
 * local in the sense that they are simply a cap in the client CSpace.
 */
#define LOCAL_HANDLE_FLAG	(2ULL)
#define LOCAL_HANDLE_SHIFT	(2)
#define IS_LOCAL_HANDLE(h)	(!!((ULONG_PTR)(h) & LOCAL_HANDLE_FLAG))
#define LOCAL_HANDLE_TO_CAP(h)						\
    (PsGetGuardValueOfCap((ULONG_PTR)(h)) ? (ULONG_PTR)(h) :		\
     (((ULONG_PTR)(h) >> LOCAL_HANDLE_SHIFT) | RtlGetThreadCSpaceGuard()))

/*
 * Maximum message length that can be sent through the seL4 message buffer
 * for the NT LPC messages. Longer messages are sent through shared memory.
 */
#define NT_LPC_MAX_SHORT_MESSAGE_LENGTH (seL4_MsgMaxLength * MWORD_BYTES)

/*
 * Server-side data structures for NtPlugPlayControl
 */

// PlugPlayControlEnumerateDevice (0x00)
typedef struct _IO_PNP_CONTROL_ENUMERATE_DEVICE_DATA {
    ULONG Flags;
    ULONG DeviceInstanceLength;	/* Including trailing NUL */
    CHAR DeviceInstance[];
} IO_PNP_CONTROL_ENUMERATE_DEVICE_DATA, *PIO_PNP_CONTROL_ENUMERATE_DEVICE_DATA;

// PlugPlayControlRegisterNewDevice (0x1)
// PlugPlayControlDeregisterDevice (0x2)
// PlugPlayControlInitializeDevice (0x3)
// PlugPlayControlStartDevice (0x4)
// PlugPlayControlUnlockDevice (0x5)
// PlugPlayControlResetDevice (0x14)
// PlugPlayControlHaltDevice (0x15)
typedef struct _IO_PNP_CONTROL_DEVICE_CONTROL_DATA {
    ULONG DeviceInstanceLength;	/* Including trailing NUL */
    CHAR DeviceInstance[];
} IO_PNP_CONTROL_DEVICE_CONTROL_DATA, *PIO_PNP_CONTROL_DEVICE_CONTROL_DATA;

// PlugPlayControlQueryAndRemoveDevice (0x06)
typedef struct _IO_PNP_CONTROL_QUERY_REMOVE_DATA {
    ULONG Flags;
    PNP_VETO_TYPE VetoType;
    ULONG DeviceInstanceLength;	/* Including trailing NUL */
    ULONG VetoNameLength;	/* Including trailing NUL */
    CHAR DeviceInstance[];	/* Veto name follows the device instance */
} IO_PNP_CONTROL_QUERY_REMOVE_DATA, *PIO_PNP_CONTROL_QUERY_REMOVE_DATA;

// PlugPlayControlUserResponse (0x07) is the same as the client-side struct

// PlugPlayControlGetInterfaceDeviceList (0x09)
typedef struct _IO_PNP_CONTROL_INTERFACE_DEVICE_LIST_DATA {
    GUID FilterGuid;
    IN OUT ULONG BufferSize;
    ULONG Flags;
    ULONG DeviceInstanceLength;	/* Including trailing NUL */
    IN OUT CHAR DeviceInstance[]; /* Output buffer follows device instance */
} IO_PNP_CONTROL_INTERFACE_DEVICE_LIST_DATA, *PIO_PNP_CONTROL_INTERFACE_DEVICE_LIST_DATA;

// PlugPlayControlProperty (0x0A)
typedef struct _IO_PNP_CONTROL_PROPERTY_DATA {
    IN OUT ULONG BufferSize;
    ULONG Property;
    ULONG DeviceInstanceLength;	/* Including trailing NUL */
    IN OUT CHAR DeviceInstance[]; /* Output buffer follows device instance */
} IO_PNP_CONTROL_PROPERTY_DATA, *PIO_PNP_CONTROL_PROPERTY_DATA;

// PlugPlayControlDeviceClassAssociation (0x0B)
typedef struct _IO_PNP_CONTROL_CLASS_ASSOCIATION_DATA {
    GUID InterfaceGuid;
    ULONG DeviceInstanceLength;	/* Including trailing NUL */
    ULONG ReferenceNameLength;	/* Including trailing NUL. Follows device instance. */
    IN OUT ULONG SymbolicLinkNameLength; /* Including trailing NUL. Follows reference name. */
    BOOLEAN Register;
    IN OUT CHAR DeviceInstance[];
} IO_PNP_CONTROL_CLASS_ASSOCIATION_DATA, *PIO_PNP_CONTROL_CLASS_ASSOCIATION_DATA;

// PlugPlayControlGetRelatedDevice (0x0C)
typedef struct _IO_PNP_CONTROL_RELATED_DEVICE_DATA {
    ULONG Relation;
    ULONG TargetDeviceInstanceLength; /* Including trailing NUL */
    IN OUT ULONG RelatedDeviceInstanceLength; /* Including trailing NUL */
    IN OUT CHAR TargetDeviceInstance[]; /* Related device name follows target name */
} IO_PNP_CONTROL_RELATED_DEVICE_DATA, *PIO_PNP_CONTROL_RELATED_DEVICE_DATA;

// PlugPlayControlGetInterfaceDeviceAlias (0x0D)
typedef struct _IO_PNP_CONTROL_INTERFACE_ALIAS_DATA {
    GUID AliasInterfaceClassGuid;
    ULONG SymbolicLinkNameLength; /* Including trailing NUL */
    IN OUT ULONG AliasSymbolicLinkNameLength; /* Including trailing NUL */
    IN OUT CHAR SymbolicLinkName[]; /* Alias symbolic name follows symbolic name */
} IO_PNP_CONTROL_INTERFACE_ALIAS_DATA, *PIO_PNP_CONTROL_INTERFACE_ALIAS_DATA;

// PlugPlayControlDeviceStatus (0x0E)
typedef struct _IO_PNP_CONTOL_STATUS_DATA {
    ULONG Operation;
    ULONG DeviceStatus;
    ULONG DeviceProblem;
    ULONG DeviceInstanceLength;	/* Including trailing NUL */
    CHAR DeviceInstance[];
} IO_PNP_CONTROL_STATUS_DATA, *PIO_PNP_CONTROL_STATUS_DATA;

// PlugPlayControlGetDeviceDepth (0x0F)
typedef struct _IO_PNP_CONTROL_DEPTH_DATA {
    ULONG Depth;
    ULONG DeviceInstanceLength;	/* Including trailing NUL */
    CHAR DeviceInstance[];
} IO_PNP_CONTROL_DEPTH_DATA, *PIO_PNP_CONTROL_DEPTH_DATA;

// PlugPlayControlQueryDeviceRelations (0x10)
typedef struct _IO_PNP_CONTROL_DEVICE_RELATIONS_DATA {
    IN OUT ULONG BufferSize;
    ULONG Relations;
    ULONG DeviceInstanceLength;	/* Including trailing NUL */
    IN OUT CHAR DeviceInstance[]; /* Output buffer follows device instance */
} IO_PNP_CONTROL_DEVICE_RELATIONS_DATA, *PIO_PNP_CONTROL_DEVICE_RELATIONS_DATA;

// PlugPlayControlRetrieveDock (0x13)
typedef struct _IO_PNP_CONTROL_RETRIEVE_DOCK_DATA {
    ULONG DeviceInstanceLength;	/* Including trailing NUL */
    CHAR DeviceInstance[];
} IO_PNP_CONTROL_RETRIEVE_DOCK_DATA, *PIO_PNP_CONTROL_RETRIEVE_DOCK_DATA;

// PlugPlayControlQueryHardwareIDs
// PlugPlayControlQueryCompatibleIDs
typedef struct _IO_PNP_CONTROL_QUERY_IDS_DATA {
    IN OUT ULONG BufferSize;
    ULONG DeviceInstanceLength;	/* Including trailing NUL */
    IN OUT CHAR DeviceInstance[]; /* Output buffer follows device instance */
} IO_PNP_CONTROL_QUERY_IDS_DATA, *PIO_PNP_CONTROL_QUERY_IDS_DATA;

/*
 * Server-side data structure for PLUGPLAY_EVENT_BLOCK
 */
typedef struct _IO_PNP_EVENT_BLOCK {
    GUID EventGuid;
    PLUGPLAY_EVENT_CATEGORY EventCategory;
    ULONG TotalSize;
    union {
	struct {
	    GUID ClassGuid;
	    CHAR SymbolicLinkName[];
	} DeviceClass;
	struct {
	    CHAR DeviceIds[];
	} TargetDevice;
	struct {
	    CHAR DeviceId[];
	} InstallDevice;
	struct {
	    CHAR DeviceIds[];
	} CustomNotification; /* Used for IoReportTargetDeviceChange */
	struct {
	    ULONG NotificationCode;
	    ULONG NotificationData;
	} PowerNotification;
	struct {
	    PNP_VETO_TYPE VetoType;
	    CHAR DeviceIdVetoNameBuffer[];
	} VetoNotification;
	struct {
	    GUID BlockedDriverGuid;
	} BlockedDriverNotification;
    };
} IO_PNP_EVENT_BLOCK, *PIO_PNP_EVENT_BLOCK;
