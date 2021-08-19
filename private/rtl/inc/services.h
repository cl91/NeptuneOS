#pragma once

#include <nt.h>
#include <gnu.h>
#include <compile_assert.h>
#include <sel4/sel4.h>

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
