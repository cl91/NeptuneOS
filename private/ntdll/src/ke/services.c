#include <ntdll.h>

#define SYSSVC_MESSAGE_BUFFER_START	((ULONG_PTR)(__sel4_ipc_buffer) + (1UL << seL4_IPCBufferSizeBits))

#define OFFSET_TO_ARGUMENT(Offset, Type) SYSSVC_MSGBUF_OFFSET_TO_ARGUMENT(SYSSVC_MESSAGE_BUFFER_START, Offset, Type)

static inline NTSTATUS KiMarshalUnicodeString(IN OUT ULONG *MsgBufOffset,
					      IN PUNICODE_STRING String,
					      OUT SYSTEM_SERVICE_ARGUMENT *Arg)
{
    ULONG BytesWritten = 0;
    if (*MsgBufOffset > SYSSVC_MESSAGE_BUFFER_SIZE) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    RET_ERR(RtlUnicodeToUTF8N(&OFFSET_TO_ARGUMENT(*MsgBufOffset, CHAR),
			      SYSSVC_MESSAGE_BUFFER_SIZE - *MsgBufOffset,
			      &BytesWritten, String->Buffer, String->Length));
    OFFSET_TO_ARGUMENT(*MsgBufOffset + BytesWritten, CHAR) = '\0';
    Arg->BufferStart = *MsgBufOffset;
    Arg->BufferSize = BytesWritten + 1;
    *MsgBufOffset += BytesWritten + 1;
    return STATUS_SUCCESS;
}

/*
 * Serialize OBJECT_ATTRIBUTES into the system service message buffer.
 *
 * Layout:
 *
 * [HANDLE RootDirectory] [ULONG Attributes] [Serialized UNICODE_STRING ObjectName]
 */
static inline NTSTATUS KiMarshalObjectAttributes(IN OUT ULONG *MsgBufOffset,
						 IN POBJECT_ATTRIBUTES ObjAttr,
						 OUT SYSTEM_SERVICE_ARGUMENT *Arg)
{
    Arg->BufferStart = *MsgBufOffset;
    OFFSET_TO_ARGUMENT(*MsgBufOffset, HANDLE) = ObjAttr->RootDirectory;
    *MsgBufOffset += sizeof(HANDLE);
    OFFSET_TO_ARGUMENT(*MsgBufOffset, ULONG) = ObjAttr->Attributes;
    *MsgBufOffset += sizeof(ULONG);
    SYSTEM_SERVICE_ARGUMENT StringArg;
    RET_ERR(KiMarshalUnicodeString(MsgBufOffset, ObjAttr->ObjectName, &StringArg));
    Arg->BufferSize = sizeof(HANDLE) + sizeof(ULONG) + StringArg.BufferSize;
    return STATUS_SUCCESS;
}

#include <ntdll_syssvc_gen.c>
