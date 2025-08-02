#pragma once

#include "ntrtl.h"
#include "ntseapi.h"

typedef struct _PORT_MESSAGE {
    ULONG TotalLength;
    ULONG Type;
} PORT_MESSAGE, *PPORT_MESSAGE;

C_ASSERT(sizeof(PORT_MESSAGE) == 8);

typedef struct _PORT_VIEW {
    HANDLE SectionHandle;
    ULONG SectionOffset;
    SIZE_T ViewSize;
    PVOID ViewBase;
    PVOID ViewRemoteBase;
} PORT_VIEW, *PPORT_VIEW;

typedef struct _REMOTE_PORT_VIEW {
    SIZE_T ViewSize;
    PVOID ViewBase;
} REMOTE_PORT_VIEW, *PREMOTE_PORT_VIEW;

#ifdef _WIN64
#define PORT_MAXIMUM_MESSAGE_LENGTH 512
#else
#define PORT_MAXIMUM_MESSAGE_LENGTH 256
#endif

#ifndef _NTOSKRNL_

/*
 * Port creation (server)
 */
NTAPI NTSYSAPI NTSTATUS NtCreatePort(OUT PHANDLE PortHandle,
				     OUT PHANDLE CommPortHandle,
				     IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
				     IN ULONG MaxMessageLength);

/*
 * Port listening (server)
 */
NTAPI NTSYSAPI NTSTATUS NtListenPort(IN HANDLE PortHandle,
				     OUT CLIENT_ID *ClientId,
				     OUT OPTIONAL PVOID ConnectionInformation,
				     IN ULONG MaxConnectionInfoLength,
				     OUT OPTIONAL PULONG ConnectionInformationLength);

/*
 * Port accept (server)
 */
NTAPI NTSYSAPI NTSTATUS NtAcceptPort(OUT OPTIONAL HANDLE *EventHandle,
				     IN HANDLE PortHandle,
				     IN ULONG_PTR PortContext,
				     IN PCLIENT_ID ClientId,
				     IN BOOLEAN AcceptConnection,
				     IN OUT OPTIONAL PPORT_VIEW ServerView,
				     OUT OPTIONAL PREMOTE_PORT_VIEW ClientView);

/*
 * Port connection (client)
 */
#ifdef _MSC_VER
NTAPI NTSYSAPI NTSTATUS NtConnectPort(IN OUT PHANDLE PortHandle,
				      IN OPTIONAL PUNICODE_STRING PortName,
				      IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
				      OUT OPTIONAL HANDLE *EventHandle,
				      IN OUT OPTIONAL PPORT_VIEW ClientView,
				      IN OUT OPTIONAL PREMOTE_PORT_VIEW ServerView,
				      OUT OPTIONAL PULONG MaxMessageLength,
				      IN OPTIONAL PVOID ConnectionInformation,
				      IN OPTIONAL ULONG ConnectionInformationLength);
#endif
NTAPI NTSYSAPI NTSTATUS NtConnectPortA(IN OUT PHANDLE PortHandle,
				       IN OPTIONAL PCSTR PortName,
				       IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
				       OUT OPTIONAL HANDLE *EventHandle,
				       IN OUT OPTIONAL PPORT_VIEW ClientView,
				       IN OUT OPTIONAL PREMOTE_PORT_VIEW ServerView,
				       OUT OPTIONAL PULONG MaxMessageLength,
				       IN OPTIONAL PVOID ConnectionInformation,
				       IN OPTIONAL ULONG ConnectionInformationLength);

/*
 * Port reply (server)
 */
NTAPI NTSYSAPI NTSTATUS NtReplyPort(IN PPORT_MESSAGE ReplyMessage,
				    IN OPTIONAL PPORT_VIEW ServerView);

/*
 * Port receive (client and server)
 */
NTAPI NTSYSAPI NTSTATUS NtReceivePort(IN HANDLE CommPortHandle,
				      OUT OPTIONAL ULONG_PTR *PortContext,
				      OUT PPORT_MESSAGE ReceivedMessage,
				      IN OPTIONAL PPORT_VIEW LocalView);

/*
 * Reply and receive message from port (server)
 */
NTAPI NTSYSAPI NTSTATUS NtReplyWaitReceivePort(IN HANDLE CommPortHandle,
					       IN OUT PPORT_MESSAGE ReplyMessage,
					       OUT OPTIONAL ULONG_PTR *PortContext,
					       OUT PPORT_MESSAGE ReceivedMessage,
					       IN OPTIONAL PPORT_VIEW ServerView);

/*
 * Send message through port (client)
 */
NTAPI NTSYSAPI NTSTATUS NtRequestPort(IN HANDLE CommPortHandle,
				      IN PPORT_MESSAGE RequestMessage,
				      IN OPTIONAL PPORT_VIEW ClientView);

/*
 * Send message through port and wait for reply (client)
 */
NTAPI NTSYSAPI NTSTATUS NtRequestWaitReceivePort(IN HANDLE CommPortHandle,
						 IN PPORT_MESSAGE RequestMessage,
						 OUT PPORT_MESSAGE ReceivedMessage,
						 IN OPTIONAL PPORT_VIEW ClientView);

#endif	/* !defined(_NTOSKRNL_) */
