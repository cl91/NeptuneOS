/*
 * Helper functions for the client side stubs of executive services.
 */

#pragma once

#include <services.h>

#define OFFSET_TO_ARG(Offset, Type) SVC_MSGBUF_OFFSET_TO_ARG((ULONG_PTR)(__sel4_ipc_buffer), Offset, Type)

static inline NTSTATUS KiMarshalUnicodeString(IN OUT ULONG *MsgBufOffset,
					      IN PUNICODE_STRING String,
					      OUT SERVICE_ARGUMENT *Arg)
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

static inline NTSTATUS KiMarshalAnsiString(IN OUT ULONG *MsgBufOffset,
					   IN PCSTR String,
					   OUT SERVICE_ARGUMENT *Arg)
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
static inline NTSTATUS KiMarshalObjectAttributes(IN OUT ULONG *MsgBufOffset,
						 IN POBJECT_ATTRIBUTES ObjAttr,
						 OUT SERVICE_ARGUMENT *Arg)
{
    Arg->BufferStart = *MsgBufOffset;
    OFFSET_TO_ARG(*MsgBufOffset, HANDLE) = ObjAttr->RootDirectory;
    *MsgBufOffset += sizeof(HANDLE);
    OFFSET_TO_ARG(*MsgBufOffset, ULONG) = ObjAttr->Attributes;
    *MsgBufOffset += sizeof(ULONG);
    SERVICE_ARGUMENT StringArg = { .Word = 0 };
    if (ObjAttr->ObjectName != NULL) {
	RET_ERR(KiMarshalUnicodeString(MsgBufOffset, ObjAttr->ObjectName, &StringArg));
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
static inline NTSTATUS KiMarshalObjectAttributesA(IN OUT ULONG *MsgBufOffset,
						  IN POBJECT_ATTRIBUTES_ANSI ObjAttr,
						  OUT SERVICE_ARGUMENT *Arg)
{
    Arg->BufferStart = *MsgBufOffset;
    OFFSET_TO_ARG(*MsgBufOffset, HANDLE) = ObjAttr->RootDirectory;
    *MsgBufOffset += sizeof(HANDLE);
    OFFSET_TO_ARG(*MsgBufOffset, ULONG) = ObjAttr->Attributes;
    *MsgBufOffset += sizeof(ULONG);
    SERVICE_ARGUMENT StringArg = { .Word = 0 };
    if (ObjAttr->ObjectName != NULL) {
	RET_ERR(KiMarshalAnsiString(MsgBufOffset, ObjAttr->ObjectName, &StringArg));
    }
    Arg->BufferSize = sizeof(HANDLE) + sizeof(ULONG) + StringArg.BufferSize;
    return STATUS_SUCCESS;
}
