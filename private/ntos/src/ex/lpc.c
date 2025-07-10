#include "ei.h"

NTSTATUS EiInitPortObject()
{
    return STATUS_SUCCESS;
}

NTSTATUS NtCreatePort(IN ASYNC_STATE AsyncState,
                      IN PTHREAD Thread,
                      OUT HANDLE *PortHandle,
                      OUT HANDLE *CommPortHandle,
                      IN OPTIONAL OB_OBJECT_ATTRIBUTES ObjectAttributes,
                      IN ULONG MaxMessageLength)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtListenPort(IN ASYNC_STATE AsyncState,
                      IN PTHREAD Thread,
                      IN HANDLE PortHandle,
                      OUT CLIENT_ID *ClientId,
                      OUT OPTIONAL PVOID ConnectionInformation,
                      IN ULONG MaxConnectionInfoLength,
                      OUT OPTIONAL ULONG *ConnectionInformationLength)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtAcceptPort(IN ASYNC_STATE AsyncState,
                      IN PTHREAD Thread,
                      IN HANDLE PortHandle,
                      IN ULONG_PTR PortContext,
                      IN PCLIENT_ID ClientId,
                      IN BOOLEAN AcceptConnection,
                      IN OUT OPTIONAL PPORT_VIEW ServerView,
                      OUT OPTIONAL REMOTE_PORT_VIEW *ClientView)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtConnectPort(IN ASYNC_STATE AsyncState,
                       IN PTHREAD Thread,
                       IN OUT PHANDLE PortHandle,
                       IN OPTIONAL PCSTR PortName,
                       IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
                       IN OUT OPTIONAL PPORT_VIEW ClientView,
                       OUT OPTIONAL REMOTE_PORT_VIEW *ServerView,
                       OUT OPTIONAL ULONG *MaxMessageLength,
                       IN OPTIONAL PVOID ConnectionInformation,
                       IN ULONG ConnectionInformationLength)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}
