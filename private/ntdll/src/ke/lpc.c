#include <ntdll.h>

FORCEINLINE NTSTATUS KiMarshalPortMessage(IN PPORT_MESSAGE PortMessage,
					  IN OPTIONAL PPORT_VIEW LocalView,
					  OUT seL4_MessageInfo_t *MessageInfo)
{
    ULONG MessageLength = PortMessage->MessageLength;
    PORT_MESSAGE ShortMsg;
    if (MessageLength > NT_LPC_MAX_SHORT_MESSAGE_LENGTH) {
	/* If the message is larger than the amount of space in seL4 message
	 * registers, send the message through the mapped shared memory. */
	ULONG DataLength = MessageLength - sizeof(PORT_MESSAGE);
	if (!LocalView || LocalView->ViewSize < DataLength) {
	    assert(FALSE);
	    return STATUS_INVALID_PARAMETER_3;
	}
	ShortMsg = *PortMessage;
	RtlCopyMemory(LocalView->ViewBase, PortMessage + 1, DataLength);
	PortMessage = &ShortMsg;
	MessageLength = sizeof(PORT_MESSAGE);
    } else {
	MessageLength = ALIGN_UP(MessageLength, ULONG_PTR);
    }

    /* Copy the message to seL4 message registers and reply to the client */
    assert(MessageLength <= NT_LPC_MAX_SHORT_MESSAGE_LENGTH);
    MessageLength /= sizeof(ULONG_PTR);
    PULONG_PTR Ptr = (PVOID)PortMessage;
    for (ULONG i = 0; i < MessageLength; i++) {
	seL4_SetMR(i, Ptr[i]);
    }
    *MessageInfo = seL4_MessageInfo_new(0, 0, 0, MessageLength);
    return STATUS_SUCCESS;
}

FORCEINLINE NTSTATUS KiUnmarshalPortMessage(IN seL4_MessageInfo_t Msg,
					    IN ULONG_PTR Badge,
					    OUT OPTIONAL ULONG_PTR *PortContext,
					    OUT PPORT_MESSAGE PortMessage,
					    IN OPTIONAL PPORT_VIEW LocalView)
{
    ULONG MessageLength = seL4_MessageInfo_get_length(Msg);
    if (MessageLength < sizeof(PORT_MESSAGE) / sizeof(ULONG_PTR)) {
	assert(FALSE);
	return STATUS_INVALID_MESSAGE;
    }
    if (PortContext) {
	*PortContext = Badge;
    }
    PULONG_PTR Ptr = (PVOID)PortMessage;
    for (ULONG i = 0; i < MessageLength; i++) {
	Ptr[i] = seL4_GetMR(i);
    }
    return STATUS_SUCCESS;
}

/*
 * Reply to client with the given message. The port replying to is
 * implicitly the one receving the last message, and the thread is
 * implicitly the one sending the last message received by the server.
 */
NTAPI NTSTATUS NtReplyPort(IN PPORT_MESSAGE ReplyMessage,
			   IN OPTIONAL PPORT_VIEW ServerView)
{
    seL4_MessageInfo_t MsgInfo;
    RET_ERR(KiMarshalPortMessage(ReplyMessage, ServerView, &MsgInfo));
    seL4_Reply(MsgInfo);
    return STATUS_SUCCESS;
}

/*
 * Port receive (client and server)
 */
NTAPI NTSTATUS NtReceivePort(IN HANDLE CommPort,
			     OUT OPTIONAL ULONG_PTR *PortContext,
			     OUT PPORT_MESSAGE ReceivedMessage,
			     IN OPTIONAL PPORT_VIEW LocalView)
{
    if (!IS_LOCAL_HANDLE(CommPort)) {
	assert(FALSE);
	return STATUS_INVALID_PORT_HANDLE;
    }
    ULONG_PTR Badge = 0;
    seL4_MessageInfo_t Msg = seL4_Recv(LOCAL_HANDLE_TO_CAP(CommPort), &Badge);
    return KiUnmarshalPortMessage(Msg, Badge, PortContext, ReceivedMessage, LocalView);
}

/*
 * Reply and receive message from port (server)
 */
NTAPI NTSTATUS NtReplyWaitReceivePort(IN HANDLE CommPort,
				      IN OUT PPORT_MESSAGE ReplyMessage,
				      OUT OPTIONAL ULONG_PTR *PortContext,
				      OUT PPORT_MESSAGE ReceivedMessage,
				      IN OPTIONAL PPORT_VIEW ServerView)
{
    if (!IS_LOCAL_HANDLE(CommPort)) {
	assert(FALSE);
	return STATUS_INVALID_PORT_HANDLE;
    }

    seL4_MessageInfo_t MsgInfo;
    RET_ERR(KiMarshalPortMessage(ReplyMessage, ServerView, &MsgInfo));
    ULONG_PTR Badge = 0;
    seL4_MessageInfo_t Msg = seL4_ReplyRecv(LOCAL_HANDLE_TO_CAP(CommPort), MsgInfo, &Badge);
    return KiUnmarshalPortMessage(Msg, Badge, PortContext, ReceivedMessage, ServerView);
}

/*
 * Send message through port (client)
 */
NTAPI NTSTATUS NtRequestPort(IN HANDLE CommPort,
			     IN PPORT_MESSAGE RequestMessage,
			     IN OPTIONAL PPORT_VIEW ClientView)
{
    if (!IS_LOCAL_HANDLE(CommPort)) {
	assert(FALSE);
	return STATUS_INVALID_PORT_HANDLE;
    }

    seL4_MessageInfo_t MsgInfo;
    RET_ERR(KiMarshalPortMessage(RequestMessage, ClientView, &MsgInfo));
    seL4_Send(LOCAL_HANDLE_TO_CAP(CommPort), MsgInfo);
    return STATUS_SUCCESS;
}

/*
 * Send message through port and wait for reply (client)
 */
NTAPI NTSTATUS NtRequestWaitReceivePort(IN HANDLE CommPort,
					IN PPORT_MESSAGE RequestMessage,
					OUT PPORT_MESSAGE ReceivedMessage,
					IN OPTIONAL PPORT_VIEW ClientView)
{
    if (!IS_LOCAL_HANDLE(CommPort)) {
	assert(FALSE);
	return STATUS_INVALID_PORT_HANDLE;
    }

    seL4_MessageInfo_t MsgInfo;
    RET_ERR(KiMarshalPortMessage(RequestMessage, ClientView, &MsgInfo));
    MsgInfo = seL4_Call(LOCAL_HANDLE_TO_CAP(CommPort), MsgInfo);
    return KiUnmarshalPortMessage(MsgInfo, 0, NULL, ReceivedMessage, ClientView);
}
