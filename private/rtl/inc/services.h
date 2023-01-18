#pragma once

#include <string.h>
#include <nt.h>
#include <gnu.h>
#include <compile_assert.h>
#include <sel4/sel4.h>

#include "private_ntstatus.h"

typedef seL4_Word MWORD;
#define MWORD_BYTES			(sizeof(MWORD))
#define MWORD_BITS			(MWORD_BYTES * 8)

#define PAGE_LOG2SIZE			(seL4_PageBits)
#define LARGE_PAGE_LOG2SIZE		(seL4_LargePageBits)
#define LARGE_PAGE_SIZE			(1ULL << LARGE_PAGE_LOG2SIZE)
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
/* This is the end of client-manageable user space. The address space
 * between USER_ADDRESS_END and seL4_UserTop is reserved for private
 * data structures that the NTOS server maps into client address space. */
#define USER_ADDRESS_END		(0xc0000000ULL)
#define HIGHEST_USER_ADDRESS		(USER_ADDRESS_END - 1)
/* Size of system dll tls region per thread is determined by the size
 * of the .tls section of the NTDLL.DLL image. */
#define SYSTEM_DLL_TLS_REGION_START	(0xc0010000ULL)
#define SYSTEM_DLL_TLS_REGION_END	(0xcff00000ULL)
/* 64K IPC buffer reserve per thread. 4K initial commit. */
#define IPC_BUFFER_START		(0xd0000000ULL)
#define IPC_BUFFER_END			(0xdfff0000ULL)
#define LOADER_SHARED_DATA_CLIENT_ADDR	IPC_BUFFER_END

#if KUSER_SHARED_DATA_CLIENT_ADDR >= USER_ADDRESS_END
#error "User shared data must be within user address space"
#endif

compile_assert(KUSER_SHARED_DATA_TOO_LARGE, USER_ADDRESS_END - LOADER_SHARED_DATA_CLIENT_ADDR >= PAGE_SIZE);

/*
 * Ipc buffer, where the seL4 IPC buffer is placed at the very beginning,
 * followed by the system service message buffer. We leave one page in
 * between IPC buffers so buffer overrun is caught as an exception.
 */
#define IPC_BUFFER_RESERVE		(2 * PAGE_SIZE)
#define IPC_BUFFER_COMMIT		(PAGE_SIZE)

/*
 * IPC buffer cannot exceed 16K because we use a SHORT to represent
 * the buffer argument offset and size. In x64 this can be changed
 * but I don't see the point of having more than 16KB IPC buffer.
 */
#if IPC_BUFFER_RESERVE > 0xFFFF
#error "IPC buffer too large"
#endif

/*
 * Maximum amount of data we can pass in the IRP itself. If user buffer
 * exceeds this size, we will directly map user buffer into server or
 * driver address space. This cannot exceed the service message buffer
 * size, and should be reasonably small (but not too small), such that
 * the overhead of mapping and unmapping exceeds the overhead of copy.
 */
#define IRP_DATA_BUFFER_SIZE	1024

/* Loader data shared between the server and NTDLL */
#define LOADER_SHARED_DATA_RESERVE	(0x10000ULL)
#define LOADER_SHARED_DATA_COMMIT	(PAGE_SIZE)

/* Private heap reserved for the Ldr component of NTDLL */
#define NTDLL_LOADER_HEAP_RESERVE	(16 * PAGE_SIZE)
#define NTDLL_LOADER_HEAP_COMMIT	(4 * PAGE_SIZE)

#ifdef _M_IX86
#define INSTRUCTION_POINTER	Eip
#define STACK_POINTER		Esp
#define BASE_POINTER		Ebp
#define FLAGS_REGISTER		EFlags
#define FASTCALL_FIRST_PARAM	Ecx
#define FASTCALL_SECOND_PARAM	Edx
#define _INSTRUCTION_POINTER	eip
#define _STACK_POINTER		esp
#define _FLAGS_REGISTER		eflags
#define _FASTCALL_FIRST_PARAM	ecx
#define _FASTCALL_SECOND_PARAM	edx
#elif defined(_M_AMD64)
#define INSTRUCTION_POINTER	Rip
#define STACK_POINTER		Rsp
#define BASE_POINTER		Rbp
#define FLAGS_REGISTER		RFlags
#define FASTCALL_FIRST_PARAM	Rcx
#define FASTCALL_SECOND_PARAM	Rdx
#define _INSTRUCTION_POINTER	rip
#define _STACK_POINTER		rsp
#define _FLAGS_REGISTER		rflags
#define _FASTCALL_FIRST_PARAM	rcx
#define _FASTCALL_SECOND_PARAM	rdx
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
    MWORD DpcMutexCap;
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
