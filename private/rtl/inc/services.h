#pragma once

#include <nt.h>
#include <gnu.h>
#include <compile_assert.h>
#include <sel4/sel4.h>

typedef seL4_Word MWORD;
#define MWORD_BYTES			(sizeof(MWORD))
#define MWORD_BITS			(MWORD_BYTES * 8)

#define PAGE_LOG2SIZE			(seL4_PageBits)
#define PAGE_SIZE			(1ULL << PAGE_LOG2SIZE)

/* All hard-coded capability slots in the client processes' CSpace go here. */
#define SYSSVC_IPC_CAP			(0x1)

/* All hard-coded addresses in client processes' address space go here. */
#define LOWEST_USER_ADDRESS		(0x00010000UL)
/* First 1MB unmapped to catch stack overflow */
#define THREAD_STACK_START		(0x00100000UL)
#define WIN32_TEB_START			(0x70000000UL)
#define WIN32_TEB_END			(0x7ffdf000UL)
#define WIN32_PEB_START			(WIN32_TEB_END)
#define HIGHEST_USER_ADDRESS		(0x7ffeffff)
/* Size of system dll tls region per thread is determined by the size
 * of the .tls section of the NTDLL.DLL image. */
#define SYSTEM_DLL_TLS_REGION_START	(0x80010000UL)
#define SYSTEM_DLL_TLS_REGION_END	(0xaff00000UL)
/* 64K IPC buffer reserve per thread. 4K initial commit. */
#define IPC_BUFFER_START		(0xb0000000UL)
#define IPC_BUFFER_END			(0xbfff0000UL)
/* We cannot put the KUSER_SHARED_DATA in the usual place (0xFFDF0000 in i386
 * or 0xFFFFF780`00000000 in amd64) so we will settle for IPC_BUFFER_END*/
#define KUSER_SHARED_DATA_CLIENT_ADDR	IPC_BUFFER_END

#define IPC_BUFFER_RESERVE		(16 * PAGE_SIZE)
#define IPC_BUFFER_COMMIT		(PAGE_SIZE)

/* Private heap reserved for the Ldr component of NTDLL */
#define NTDLL_LOADER_HEAP_RESERVE	(16 * PAGE_SIZE)
#define NTDLL_LOADER_HEAP_COMMIT	(4 * PAGE_SIZE)

typedef struct _NTDLL_PROCESS_INIT_INFO {
    MWORD LoaderHeapStart;
    MWORD ProcessHeapStart;
    MWORD ProcessHeapReserve;
    MWORD ProcessHeapCommit;
    HANDLE CriticalSectionLockSemaphore;
} NTDLL_PROCESS_INIT_INFO, *PNTDLL_PROCESS_INIT_INFO;

#if seL4_PageBits <= seL4_IPCBufferSizeBits
#error "seL4 IPC Buffer too large (must be no larger than half of a 4K page)"
#endif

/* System service message buffer sits immediately after the seL4 IPC buffer */
#define SEL4_IPC_BUFFER_SIZE		(1UL << seL4_IPCBufferSizeBits)
#define SYSSVC_MESSAGE_BUFFER_SIZE	((1UL << seL4_PageBits) - SEL4_IPC_BUFFER_SIZE)

/*
 * Points to a buffer (within the system service message buffer) which stores
 * an argument to the system service. The client stub copies the client data
 * into the buffer and passes the pointer to the server.
 */
typedef union _SYSTEM_SERVICE_ARGUMENT {
    struct {
	USHORT BufferStart; /* Relative to the beginning of svc msg buffer */
	USHORT BufferSize;
    };
    MWORD Word;
} SYSTEM_SERVICE_ARGUMENT;

assert_size_correct(SYSTEM_SERVICE_ARGUMENT, MWORD_BYTES);

static inline BOOLEAN KiSystemServiceValidateArgument(IN MWORD MsgWord)
{
    SYSTEM_SERVICE_ARGUMENT Arg;
    Arg.Word = MsgWord;
    if (((ULONG)(Arg.BufferStart) + Arg.BufferSize) > SYSSVC_MESSAGE_BUFFER_SIZE) {
	return FALSE;
    }
    return TRUE;
}

#define SYSSVC_MSGBUF_OFFSET_TO_ARGUMENT(IpcBufAddr, Offset, Type) (*((Type *)(IpcBufAddr + SEL4_IPC_BUFFER_SIZE + (Offset))))

static inline PVOID KiSystemServiceGetArgument(IN MWORD IpcBufferAddr,
					       IN MWORD MsgWord)
{
    if (MsgWord == 0) {
	return NULL;
    }
    SYSTEM_SERVICE_ARGUMENT Arg;
    Arg.Word = MsgWord;
    return &SYSSVC_MSGBUF_OFFSET_TO_ARGUMENT(IpcBufferAddr, Arg.BufferStart, VOID);
}

static inline NTSTATUS KiSystemServiceMarshalArgument(IN MWORD IpcBufferAddr,
						      IN OUT ULONG *MsgBufOffset,
						      IN PVOID Argument,
						      IN MWORD ArgSize,
						      OUT SYSTEM_SERVICE_ARGUMENT *SvcArg)
{
    if (*MsgBufOffset > SYSSVC_MESSAGE_BUFFER_SIZE) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    if (SYSSVC_MESSAGE_BUFFER_SIZE - *MsgBufOffset < ArgSize) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    SvcArg->Word = 0;
    memcpy(&SYSSVC_MSGBUF_OFFSET_TO_ARGUMENT(IpcBufferAddr, *MsgBufOffset, VOID), Argument, ArgSize);
    SvcArg->BufferStart = *MsgBufOffset;
    SvcArg->BufferSize = ArgSize;
    *MsgBufOffset += ArgSize;
    return STATUS_SUCCESS;
}

#include <syssvc_gen.h>

compile_assert(TOO_MANY_SYSTEM_SERVICES, NUMBER_OF_SYSTEM_SERVICES < 0x1000UL);
