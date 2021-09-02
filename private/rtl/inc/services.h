#pragma once

#include <nt.h>
#include <gnu.h>
#include <compile_assert.h>
#include <sel4/sel4.h>

typedef seL4_Word MWORD;
#define MWORD_BYTES	(sizeof(MWORD))
#define MWORD_BITS	(MWORD_BYTES * 8)

/* All hard-coded capability slots in the client processes' CSpace go here. */
#define SYSSVC_IPC_CAP			(0x1)

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
