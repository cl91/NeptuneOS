#include "ei.h"

NTSTATUS NtPowerInformation(IN ASYNC_STATE AsyncState, IN PTHREAD Thread,
			    IN POWER_INFORMATION_LEVEL PowerInformationLevel,
			    IN OPTIONAL PVOID InputBuffer, IN ULONG InputBufferLength,
			    OUT OPTIONAL PVOID OutputBuffer, IN ULONG OutputBufferLength)
{
    UNIMPLEMENTED;
}

NTSTATUS NtInitiatePowerAction(IN ASYNC_STATE AsyncState, IN PTHREAD Thread,
			       IN POWER_ACTION SystemAction,
			       IN SYSTEM_POWER_STATE MinSystemState, IN ULONG Flags,
			       IN BOOLEAN Asynchronous)
{
    UNIMPLEMENTED;
}

NTSTATUS NtGetDevicePowerState(IN ASYNC_STATE AsyncState, IN PTHREAD Thread,
			       IN HANDLE Device, IN PDEVICE_POWER_STATE PowerState)
{
    UNIMPLEMENTED;
}

NTSTATUS NtRequestDeviceWakeup(IN ASYNC_STATE AsyncState, IN PTHREAD Thread,
			       IN HANDLE Device)
{
    UNIMPLEMENTED;
}

NTSTATUS NtRequestWakeupLatency(IN ASYNC_STATE AsyncState, IN PTHREAD Thread,
				IN LATENCY_TIME Latency)
{
    UNIMPLEMENTED;
}

NTSTATUS NtCancelDeviceWakeupRequest(IN ASYNC_STATE AsyncState, IN PTHREAD Thread,
				     IN HANDLE Device)
{
    UNIMPLEMENTED;
}

NTSTATUS NtSetThreadExecutionState(IN ASYNC_STATE AsyncState, IN PTHREAD Thread,
				   IN EXECUTION_STATE ExecutionState,
				   OUT PEXECUTION_STATE PreviousState)
{
    UNIMPLEMENTED;
}
