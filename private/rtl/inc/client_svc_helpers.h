/*
 * Helper functions for the client side stubs of executive services.
 */

#pragma once

#include <services.h>

#define OFFSET_TO_ARG(Offset, Type) SVC_MSGBUF_OFFSET_TO_ARG((ULONG_PTR)(__sel4_ipc_buffer), Offset, Type)

static inline NTSTATUS KiServiceMarshalArgument(OUT SERVICE_ARGUMENT *SvcArg,
						IN OPTIONAL PVOID Argument,
						IN MWORD ArgSize,
						IN OUT ULONG *MsgBufOffset)
{
    if (*MsgBufOffset > SVC_MSGBUF_SIZE) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    if (SVC_MSGBUF_SIZE - *MsgBufOffset < ArgSize) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    if (Argument != NULL) {
	memcpy(&OFFSET_TO_ARG(*MsgBufOffset, VOID), Argument, ArgSize);
    }
    SvcArg->BufferStart = *MsgBufOffset;
    SvcArg->BufferSize = ArgSize;
    *MsgBufOffset += ArgSize;
    return STATUS_SUCCESS;
}

static inline NTSTATUS KiMarshalUnicodeString(OUT SERVICE_ARGUMENT *Arg,
					      IN PUNICODE_STRING String,
					      IN OUT ULONG *MsgBufOffset)
{
    assert(MsgBufOffset != NULL);
    assert(String != NULL);
    assert(String->Buffer != NULL);
    assert(Arg != NULL);
    ULONG BytesWritten = 0;
    if (*MsgBufOffset > SVC_MSGBUF_SIZE) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    RET_ERR(RtlUnicodeToUTF8N(&OFFSET_TO_ARG(*MsgBufOffset, CHAR),
			      SVC_MSGBUF_SIZE - *MsgBufOffset,
			      &BytesWritten, String->Buffer, String->Length));
    OFFSET_TO_ARG(*MsgBufOffset + BytesWritten, CHAR) = '\0';
    Arg->BufferStart = *MsgBufOffset;
    Arg->BufferSize = BytesWritten + 1;
    *MsgBufOffset += BytesWritten + 1;
    return STATUS_SUCCESS;
}

static inline NTSTATUS KiMarshalAnsiString(OUT SERVICE_ARGUMENT *Arg,
					   IN PCSTR String,
					   IN OUT ULONG *MsgBufOffset)
{
    assert(MsgBufOffset != NULL);
    assert(String != NULL);
    assert(Arg != NULL);
    ULONG Length = strlen(String) + 1;
    if ((*MsgBufOffset + Length) > SVC_MSGBUF_SIZE) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    memcpy(&OFFSET_TO_ARG(*MsgBufOffset, CHAR), String, Length);
    Arg->BufferStart = *MsgBufOffset;
    Arg->BufferSize = Length;
    *MsgBufOffset += Length;
    return STATUS_SUCCESS;
}

/*
 * Serialize OBJECT_ATTRIBUTES into the executive service message buffer.
 *
 * Layout:
 *
 * [HANDLE RootDirectory] [ULONG Attributes] [Serialized UNICODE_STRING ObjectName]
 */
static inline NTSTATUS KiMarshalObjectAttributes(OUT SERVICE_ARGUMENT *Arg,
						 IN POBJECT_ATTRIBUTES ObjAttr,
						 IN OUT ULONG *MsgBufOffset)
{
    Arg->BufferStart = *MsgBufOffset;
    OFFSET_TO_ARG(*MsgBufOffset, HANDLE) = ObjAttr->RootDirectory;
    *MsgBufOffset += sizeof(HANDLE);
    OFFSET_TO_ARG(*MsgBufOffset, ULONG) = ObjAttr->Attributes;
    *MsgBufOffset += sizeof(ULONG);
    SERVICE_ARGUMENT StringArg = { .Word = 0 };
    if (ObjAttr->ObjectName != NULL && ObjAttr->ObjectName->Buffer != NULL) {
	RET_ERR(KiMarshalUnicodeString(&StringArg, ObjAttr->ObjectName, MsgBufOffset));
    }
    Arg->BufferSize = sizeof(HANDLE) + sizeof(ULONG) + StringArg.BufferSize;
    return STATUS_SUCCESS;
}

/*
 * Serialize OBJECT_ATTRIBUTES_ANSI into the executive service message buffer.
 *
 * Layout:
 *
 * [HANDLE RootDirectory] [ULONG Attributes] [Serialized PCSTR ObjectName]
 */
static inline NTSTATUS KiMarshalObjectAttributesA(OUT SERVICE_ARGUMENT *Arg,
						  IN POBJECT_ATTRIBUTES_ANSI ObjAttr,
						  IN OUT ULONG *MsgBufOffset)
{
    Arg->BufferStart = *MsgBufOffset;
    OFFSET_TO_ARG(*MsgBufOffset, HANDLE) = ObjAttr->RootDirectory;
    *MsgBufOffset += sizeof(HANDLE);
    OFFSET_TO_ARG(*MsgBufOffset, ULONG) = ObjAttr->Attributes;
    *MsgBufOffset += sizeof(ULONG);
    SERVICE_ARGUMENT StringArg = { .Word = 0 };
    if (ObjAttr->ObjectName != NULL) {
	RET_ERR(KiMarshalAnsiString(&StringArg, ObjAttr->ObjectName, MsgBufOffset));
    }
    Arg->BufferSize = sizeof(HANDLE) + sizeof(ULONG) + StringArg.BufferSize;
    return STATUS_SUCCESS;
}

/*
 * Returns TRUE if the pointer falls in the service message buffer
 */
static inline BOOLEAN KiPtrInSvcMsgBuf(IN PVOID Ptr)
{
    return ((MWORD)Ptr >= (MWORD)__sel4_ipc_buffer) &&
	((MWORD)Ptr < ((MWORD)__sel4_ipc_buffer + IPC_BUFFER_COMMIT));
}

static inline NTSTATUS KiServiceMarshalBuffer(IN PVOID ClientBuffer,
					      IN MWORD BufferSize,
					      OUT SERVICE_ARGUMENT *BufferArg,
					      OUT SERVICE_ARGUMENT *SizeArg,
					      IN BOOLEAN InParam,
					      OUT ULONG *MsgBufOffset)
{
    if (KiPtrInSvcMsgBuf(ClientBuffer)) {
	return STATUS_INVALID_USER_BUFFER;
    }
    if (BufferSize == 0) {
	return STATUS_INVALID_PARAMETER;
    }
    /* If the buffer size exceeds what we can carry with the IRP,
     * or if it cannot fit into the service message buffer, simply
     * send the original client buffer pointer to the server and let
     * the server worry about mapping client buffers for IO. */
    if (BufferSize < IRP_DATA_BUFFER_SIZE ||
	(*MsgBufOffset + BufferSize >= SVC_MSGBUF_SIZE)) {
	BufferArg->Word = (MWORD)ClientBuffer;
    } else {
	/* Otherwise, for IN parameters we copy the client data to the
	 * IPC buffer. For OUT parameters we simply allocate space. */
	BufferArg->Word = (MWORD)&OFFSET_TO_ARG(*MsgBufOffset, VOID);
	if (InParam) {
	    memcpy((PVOID)BufferArg->Word, ClientBuffer, BufferSize);
	}
	*MsgBufOffset += BufferSize;
    }
    SizeArg->Word = BufferSize;
    return STATUS_SUCCESS;
}

static inline VOID KiServiceUnmarshalBuffer(IN PVOID ClientBuffer,
					    IN SERVICE_ARGUMENT BufferArg,
					    IN MWORD BufferSize)
{
    assert(ClientBuffer != NULL);
    if (KiPtrInSvcMsgBuf((PVOID)BufferArg.Word)) {
	assert(BufferArg.Word >= (MWORD)&OFFSET_TO_ARG(0, VOID));
	assert(BufferArg.Word < (MWORD)&OFFSET_TO_ARG(SVC_MSGBUF_SIZE, VOID));
	assert(BufferArg.Word + BufferSize < (MWORD)&OFFSET_TO_ARG(SVC_MSGBUF_SIZE, VOID));
	memcpy(ClientBuffer, (PVOID)BufferArg.Word, BufferSize);
    }
}

static inline VOID KiDeliverApc(IN ULONG MsgBufOffset,
                                IN ULONG NumApc)
{
    assert(NumApc > 0);
    APC_OBJECT Apc[MAX_APC_PER_DELIVERY];
    memcpy(Apc, &OFFSET_TO_ARG(MsgBufOffset, APC_OBJECT), NumApc * sizeof(APC_OBJECT));
    for (SHORT i = 0; i < NumApc; i++) {
        assert(Apc[i].ApcRoutine != NULL);
        if (Apc[i].ApcRoutine != NULL) {
            DbgTrace("Delivering APC Routine %p Arguments %p %p %p\\n", Apc->ApcRoutine,
                     Apc->ApcContext[0], Apc->ApcContext[1], Apc->ApcContext[2]);
            (Apc[i].ApcRoutine)(Apc[i].ApcContext[0], Apc[i].ApcContext[1], Apc[i].ApcContext[2]);
        }
    }
}
