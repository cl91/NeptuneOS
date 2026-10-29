#pragma once

#include <ntrtl.h>
#include <ntseapi.h>
#include <ntexapi.h>

/*
 * Port Object Access Masks
 */
#define PORT_CONNECT                    0x1
#define PORT_ALL_ACCESS                 (STANDARD_RIGHTS_REQUIRED | \
                                         SYNCHRONIZE | \
                                         PORT_CONNECT)

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

#define LPC_MAX_MESSAGE_LENGTH PORT_MAXIMUM_MESSAGE_LENGTH
#define LPC_MAX_DATA_LENGTH (LPC_MAX_MESSAGE_LENGTH - sizeof(PORT_MESSAGE))

/*
 * LPC Message Types
 */
typedef enum _LPC_TYPE {
    LPC_NEW_MESSAGE,
    LPC_REQUEST,
    LPC_REPLY,
    LPC_DATAGRAM,
    LPC_LOST_REPLY,
    LPC_PORT_CLOSED,
    LPC_CLIENT_DIED,
    LPC_EXCEPTION,
    LPC_DEBUG_EVENT,
    LPC_ERROR_EVENT,
    LPC_CONNECTION_REQUEST,
    LPC_CONNECTION_REFUSED,
    LPC_MAXIMUM
} LPC_TYPE;

/*
 * Client Died LPC Message
 */
typedef struct _CLIENT_DIED_MSG {
    PORT_MESSAGE Header;
    LARGE_INTEGER CreateTime;
} CLIENT_DIED_MSG, *PCLIENT_DIED_MSG;

/*
 * Hard Error LPC Message
 */
typedef struct _HARDERROR_MSG {
    PORT_MESSAGE Header;
    NTSTATUS Status;
    LARGE_INTEGER ErrorTime;
    ULONG ValidResponseOptions;
    ULONG Response;
    ULONG NumberOfParameters;
    ULONG UnicodeStringParameterMask;
    ULONG_PTR Parameters[MAXIMUM_HARDERROR_PARAMETERS];
} HARDERROR_MSG, *PHARDERROR_MSG;

#ifndef _NTOSKRNL_

/*
 * Port creation (server)
 */
NTAPI NTSYSAPI NTSTATUS NtCreatePort(OUT PHANDLE PortHandle,
				     OUT PLOCAL_HANDLE CommPortHandle,
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
 * Port opening (client)
 */
#ifdef _MSC_VER
NTAPI NTSYSAPI NTSTATUS NtOpenPort(OUT HANDLE *PortHandle,
				   IN POBJECT_ATTRIBUTES ObjectAttributes,
				   IN ACCESS_MASK DesiredAccess);
#endif
NTAPI NTSYSAPI NTSTATUS NtOpenPortA(OUT HANDLE *PortHandle,
				    IN POBJECT_ATTRIBUTES_ANSI ObjectAttributes,
				    IN ACCESS_MASK DesiredAccess);

/*
 * Port connection (client)
 */
NTAPI NTSYSAPI NTSTATUS NtConnectPort(IN HANDLE PortHandle,
				      IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
				      OUT LOCAL_HANDLE *CommPortHandle,
				      OUT OPTIONAL HANDLE *EventHandle,
				      IN OUT OPTIONAL PPORT_VIEW ClientView,
				      IN OPTIONAL PSID RequiredServerSid,
				      IN OUT OPTIONAL PREMOTE_PORT_VIEW ServerView,
				      OUT OPTIONAL PULONG MaxMessageLength,
				      IN OPTIONAL PVOID ConnectionInformation,
				      IN OPTIONAL ULONG ConnectionInformationLength);

/*
 * Port disconnection (client)
 */
NTAPI NTSYSAPI NTSTATUS NtDisconnectPort(IN LOCAL_HANDLE CommPortHandle);

/*
 * Port reply (server)
 */
NTAPI NTSYSAPI NTSTATUS NtReplyPort(IN PPORT_MESSAGE ReplyMessage,
				    IN OPTIONAL PPORT_VIEW ServerView);

/*
 * Port receive (client and server)
 */
NTAPI NTSYSAPI NTSTATUS NtReceivePort(IN LOCAL_HANDLE CommPortHandle,
				      OUT OPTIONAL ULONG_PTR *PortContext,
				      OUT PPORT_MESSAGE ReceivedMessage,
				      IN OPTIONAL PPORT_VIEW LocalView);

/*
 * Reply and receive message from port (server)
 */
NTAPI NTSYSAPI NTSTATUS NtReplyWaitReceivePort(IN LOCAL_HANDLE CommPortHandle,
					       IN OUT PPORT_MESSAGE ReplyMessage,
					       OUT OPTIONAL ULONG_PTR *PortContext,
					       OUT PPORT_MESSAGE ReceivedMessage,
					       IN OPTIONAL PPORT_VIEW ServerView);

/*
 * Send message through port (client)
 */
NTAPI NTSYSAPI NTSTATUS NtRequestPort(IN LOCAL_HANDLE CommPortHandle,
				      IN PPORT_MESSAGE RequestMessage,
				      IN OPTIONAL PPORT_VIEW ClientView);

/*
 * Send message through port and wait for reply (client)
 */
NTAPI NTSYSAPI NTSTATUS NtRequestWaitReceivePort(IN LOCAL_HANDLE CommPortHandle,
						 IN PPORT_MESSAGE RequestMessage,
						 OUT PPORT_MESSAGE ReceivedMessage,
						 IN OPTIONAL PPORT_VIEW ClientView);

#endif	/* !defined(_NTOSKRNL_) */
