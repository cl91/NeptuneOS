#pragma once

#include <nt.h>
#include <gnu.h>
#include <compile_assert.h>
#include <sel4/sel4.h>

/* All hard-coded addresses in client processes' address space go here. */
#define LOWEST_USER_ADDRESS		(0x00010000)
#define WIN32_TEB_START			(0x70000000)
#define WIN32_TEB_END			(0x7ffdf000)
#define WIN32_PEB_START			(WIN32_TEB_END)
/* First 1MB of 0x80000000 unmapped to catch stack overflow */
#define THREAD_STACK_REGION_START	(0x80100000)
/* 1G thread space ~ 1024 threads with 1M stack */
#define THREAD_STACK_REGION_END		(0xcff00000)
/* 1MB-64K after thread stack region unmapped to catch stack underflow */
#define USER_SHARED_DATA		(0xcfff0000)
/* 64KB-4KB following user shared data is unmapped */
#define SYSTEM_DLL_IMAGE_START		(0xd0000000)
/* Subsystem dlls (kernel32.dll etc) follow NTDLL. 128MB */
#define SUBSYSTEM_DLL_IMAGE_END		(0xd8000000)
/* 4K system dll tls region per thread. 64MB == 16K threads */
#define SYSTEM_DLL_TLS_REGION_START	(SUBSYSTEM_DLL_IMAGE_END)
#define SYSTEM_DLL_TLS_REGION_END	(0xdc000000)
/* 4K IPC buffer per thread. 64MB == 16K threads */
#define IPC_BUFFER_START		(SYSTEM_DLL_TLS_REGION_END)
#define IPC_BUFFER_END			(0xe0000000)
#define HIGHEST_USER_ADDRESS		(0xe0000000)

/* All hard-coded capability slots in the client processes' CSpace go here. */
#define SYSSVC_IPC_CAP			(0x1)

#if IPC_BUFFER_END > HIGHEST_USER_ADDRESS
#error "IPC_BUFFER_END must be smaller than HIGHEST_USER_ADDRESS"
#endif

typedef enum _SYSTEM_SERVICE_NUMBER {
    NT_DISPLAY_STRING,
    NUMBER_OF_SYSTEM_SERVICES
} SYSTEM_SERVICE_NUMBER;

compile_assert(TOO_MANY_SYSTEM_SERVICES, NUMBER_OF_SYSTEM_SERVICES < 0x1000UL);

/*
 * Points to a string buffer within the system service message buffer
 */
typedef union _SYSTEM_SERVICE_STRING_BUFFER {
    struct {
	USHORT BufferStart;
	USHORT BufferLength;
    };
    ULONG Word;
} SYSTEM_SERVICE_STRING_BUFFER;

assert_size_correct(SYSTEM_SERVICE_STRING_BUFFER, 4);

#if seL4_PageBits <= seL4_IPCBufferSizeBits
#error "seL4 IPC Buffer too large (must be no larger than half of a 4K page)"
#endif

#define SYSSVC_MESSAGE_BUFFER_START	((ULONG_PTR)(__sel4_ipc_buffer) + (1UL << seL4_IPCBufferSizeBits))
#define SYSSVC_MESSAGE_BUFFER_SIZE	(1UL << (seL4_PageBits - seL4_IPCBufferSizeBits))

/* TODO: Add thread local variable KeSystemServiceMessageBuffer */
static inline char *KeServiceMessageGetString(IN SYSTEM_SERVICE_STRING_BUFFER StringBuffer)
{
    return (char *) SYSSVC_MESSAGE_BUFFER_START + StringBuffer.BufferStart;
}
