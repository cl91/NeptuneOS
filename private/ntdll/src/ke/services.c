#include <ntdll.h>

#define SYSSVC_MESSAGE_BUFFER_START	((ULONG_PTR)(__sel4_ipc_buffer) + (1UL << seL4_IPCBufferSizeBits))

static inline NTSTATUS KiMarshalUnicodeString(IN OUT ULONG *MsgBufOffset,
					      IN PUNICODE_STRING String,
					      OUT SYSTEM_SERVICE_ARGUMENT_BUFFER *StringArgBuf)
{
    ULONG BytesWritten = 0;
    assert(*MsgBufOffset <= SYSSVC_MESSAGE_BUFFER_SIZE);
    RET_ERR(RtlUnicodeToUTF8N((PCHAR) (SYSSVC_MESSAGE_BUFFER_START + *MsgBufOffset),
			      SYSSVC_MESSAGE_BUFFER_SIZE - *MsgBufOffset,
			      &BytesWritten, String->Buffer, String->Length));
    ((PCHAR)(SYSSVC_MESSAGE_BUFFER_START))[*MsgBufOffset + BytesWritten] = '\0';
    StringArgBuf->BufferStart = *MsgBufOffset;
    StringArgBuf->BufferSize = BytesWritten + 1;
    *MsgBufOffset += BytesWritten + 1;
    return STATUS_SUCCESS;
}

#include <ntdll_syssvc_gen.c>
