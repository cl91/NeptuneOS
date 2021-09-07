#pragma once

#include <nt.h>
#include <gnu.h>
#include <compile_assert.h>
#include <sel4/sel4.h>

typedef seL4_Word MWORD;
#define MWORD_BYTES	(sizeof(MWORD))
#define MWORD_BITS	(MWORD_BYTES * 8)

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
#define IPC_BUFFER_END			(0xe0000000UL)

#define IPC_BUFFER_RESERVE		(16 * PAGE_SIZE)
#define IPC_BUFFER_COMMIT		(PAGE_SIZE)

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
typedef union _SYSTEM_SERVICE_ARGUMENT_BUFFER {
    struct {
	USHORT BufferStart; /* Relative to the beginning of svc msg buffer */
	USHORT BufferSize;
    };
    ULONG Word;
} SYSTEM_SERVICE_ARGUMENT_BUFFER;

assert_size_correct(SYSTEM_SERVICE_ARGUMENT_BUFFER, 4);

#include <syssvc_gen.h>

compile_assert(TOO_MANY_SYSTEM_SERVICES, NUMBER_OF_SYSTEM_SERVICES < 0x1000UL);
