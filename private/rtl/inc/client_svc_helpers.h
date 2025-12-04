/*
 * Helper functions for the client side stubs of executive services.
 */

#pragma once

#include <services.h>
#include <util.h>

#define OFFSET_TO_ARG(Offset, Type)				\
    SVC_MSGBUF_OFFSET_TO_ARG(seL4_GetIPCBuffer(), Offset, Type)

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
	memcpy(&OFFSET_TO_ARG(*MsgBufOffset, CHAR), Argument, ArgSize);
    }
    SvcArg->BufferStart = *MsgBufOffset;
    SvcArg->BufferSize = ArgSize;
    *MsgBufOffset += ArgSize;
    return STATUS_SUCCESS;
}

static inline NTSTATUS KiMarshalThreadContext(OUT SERVICE_ARGUMENT *SvcArg,
					      IN PCONTEXT Context,
					      IN OUT ULONG *MsgBufOffset)
{
    VOID KiPopulateThreadContext(OUT PTHREAD_CONTEXT ThreadContext,
				 IN PCONTEXT Context);
    if (*MsgBufOffset > SVC_MSGBUF_SIZE) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    if (SVC_MSGBUF_SIZE - *MsgBufOffset < sizeof(THREAD_CONTEXT)) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    if (!Context) {
	return STATUS_INVALID_PARAMETER;
    }
    KiPopulateThreadContext(&OFFSET_TO_ARG(*MsgBufOffset, THREAD_CONTEXT), Context);
    SvcArg->BufferStart = *MsgBufOffset;
    SvcArg->BufferSize = sizeof(THREAD_CONTEXT);
    *MsgBufOffset += sizeof(THREAD_CONTEXT);
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
    return ((MWORD)Ptr >= (MWORD)seL4_GetIPCBuffer()) &&
	((MWORD)Ptr < ((MWORD)seL4_GetIPCBuffer() + IPC_BUFFER_COMMIT));
}

static inline NTSTATUS KiServiceMarshalBuffer(IN OPTIONAL PVOID ClientBuffer,
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
	/* Some system services accepts a zero BufferSize. Service will
	 * typically set the result size to the correct buffer size so
	 * client can allocate the right amount of memory. */
	return ClientBuffer != NULL ? STATUS_INVALID_PARAMETER : STATUS_SUCCESS;
    }
    if (ClientBuffer == NULL) {
	return BufferSize ? STATUS_INVALID_PARAMETER : STATUS_SUCCESS;
    }
    /* If the buffer size exceeds what we can carry with the IRP,
     * or if it cannot fit into the service message buffer, simply
     * send the original client buffer pointer to the server and let
     * the server worry about mapping client buffers for IO. */
    if (BufferSize >= IRP_DATA_BUFFER_SIZE ||
	(*MsgBufOffset + BufferSize >= SVC_MSGBUF_SIZE)) {
	BufferArg->Word = (MWORD)ClientBuffer;
    } else {
	/* Otherwise, for IN parameters we copy the client data to the
	 * IPC buffer. For OUT parameters we simply allocate space. */
	BufferArg->Word = (MWORD)&OFFSET_TO_ARG(*MsgBufOffset, CHAR);
	if (InParam) {
	    memcpy((PVOID)BufferArg->Word, ClientBuffer, BufferSize);
	}
	*MsgBufOffset += BufferSize;
    }
    SizeArg->Word = BufferSize;
    return STATUS_SUCCESS;
}

static inline NTSTATUS KiServiceUnmarshalBuffer64(IN PVOID ClientBuffer,
						  IN SERVICE_ARGUMENT BufferArg,
						  IN NTSTATUS Status,
						  IN MWORD BufferLength,
						  IN MWORD *ResultLength)
{
    assert(ClientBuffer != NULL);
    MWORD SizeToCopy = (Status != STATUS_BUFFER_OVERFLOW && Status != STATUS_BUFFER_TOO_SMALL) ?
	*ResultLength : BufferLength;
    if (KiPtrInSvcMsgBuf((PVOID)BufferArg.Word)) {
	assert(BufferArg.Word >= (MWORD)&OFFSET_TO_ARG(0, CHAR));
	assert(BufferArg.Word < (MWORD)&OFFSET_TO_ARG(SVC_MSGBUF_SIZE, CHAR));
	assert(BufferArg.Word + SizeToCopy < (MWORD)&OFFSET_TO_ARG(SVC_MSGBUF_SIZE, CHAR));
	memcpy(ClientBuffer, (PVOID)BufferArg.Word, SizeToCopy);
    }
    return STATUS_SUCCESS;
}

static inline VOID KiServiceUnmarshalBuffer5(IN PVOID ClientBuffer,
					     IN SERVICE_ARGUMENT BufferArg,
					     IN NTSTATUS Status,
					     IN MWORD BufferLength,
					     IN ULONG *pResultLength)
{
    MWORD ResultLength = *pResultLength;
    KiServiceUnmarshalBuffer64(ClientBuffer, BufferArg, Status, BufferLength, &ResultLength);
}

static inline VOID KiServiceUnmarshalBuffer6(IN PVOID ClientBuffer,
					     IN SERVICE_ARGUMENT BufferArg,
					     IN NTSTATUS Status,
					     IN MWORD BufferLength,
					     IN ULONG *ResultLength,
					     IN UNUSED MWORD BufferType)
{
    KiServiceUnmarshalBuffer5(ClientBuffer, BufferArg, Status, BufferLength, ResultLength);
}

#define KI_GET_7TH_ARG(_1,_2,_3,_4,_5,_6,_7,...)	_7
#define KiServiceUnmarshalBuffer(...)				\
    ({								\
	KI_GET_7TH_ARG(__VA_ARGS__, KiServiceUnmarshalBuffer6,	\
		       KiServiceUnmarshalBuffer5)(__VA_ARGS__);	\
	STATUS_SUCCESS;						\
    })

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
