#include "ei.h"

NTSTATUS NtCreateDebugObject(IN ASYNC_STATE AsyncState,
			     IN PTHREAD Thread,
			     OUT HANDLE *DebugHandle,
			     IN ACCESS_MASK DesiredAccess,
			     IN OB_OBJECT_ATTRIBUTES ObjectAttributes,
			     IN ULONG Flags)
{
    UNIMPLEMENTED;
}

NTSTATUS NtDebugActiveProcess(IN ASYNC_STATE AsyncState,
			      IN PTHREAD Thread,
			      IN HANDLE Process,
			      IN HANDLE DebugObject)
{
    UNIMPLEMENTED;
}

NTSTATUS NtDebugContinue(IN ASYNC_STATE AsyncState,
			 IN PTHREAD Thread,
			 IN HANDLE DebugObject,
			 IN PCLIENT_ID AppClientId,
			 IN NTSTATUS ContinueStatus)
{
    UNIMPLEMENTED;
}

NTSTATUS NtWaitForDebugEvent(IN ASYNC_STATE AsyncState,
			     IN PTHREAD Thread,
			     IN HANDLE DebugObject,
			     IN BOOLEAN Alertable,
			     IN OPTIONAL PLARGE_INTEGER Timeout,
			     OUT DBGUI_WAIT_STATE_CHANGE *StateChange)
{
    UNIMPLEMENTED;
}

NTSTATUS NtRemoveProcessDebug(IN ASYNC_STATE AsyncState,
			      IN PTHREAD Thread,
			      IN HANDLE Process,
			      IN HANDLE DebugObject)
{
    UNIMPLEMENTED;
}

NTSTATUS NtSetInformationDebugObject(IN ASYNC_STATE AsyncState, IN PTHREAD Thread,
				     IN HANDLE DebugObject,
				     IN DEBUG_OBJECT_INFORMATION_CLASS InformationClass,
				     IN PVOID Information, IN ULONG InformationLength,
				     OUT OPTIONAL PULONG ReturnLength)
{
    UNIMPLEMENTED;
}
