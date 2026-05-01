#include <psxdllp.h>

VOID PsxExitProcess(INT Status)
{
    NtTerminateProcess(NtCurrentProcess(), Status);
}

NTSTATUS PsxConnectPort(OUT PHANDLE PortHandle,
			OUT PLOCAL_HANDLE CommPortHandle)
{
    ULONG MaxMessageLength = 0;
    SECURITY_QUALITY_OF_SERVICE SecurityQos = {};
    OBJECT_ATTRIBUTES_ANSI ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, "\\PsxssApi", 0, NULL, NULL);
    NTSTATUS Status = NtOpenPortA(PortHandle, &ObjectAttributes, 0);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    Status = NtConnectPort(*PortHandle, &SecurityQos, CommPortHandle,
			   NULL, NULL, NULL, &MaxMessageLength, NULL, 0);
    return Status;
}

VOID PsxProcessStartup()
{
    NtDisplayStringA("Hello from POSIX process\n");
    PPEB Peb = NtCurrentPeb();
    Peb->SyscallTable.ExitProcess = PsxExitProcess;

    HANDLE PortHandle = NULL;
    LOCAL_HANDLE CommPortHandle = 0;
    NTSTATUS Status = PsxConnectPort(&PortHandle, &CommPortHandle);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }
    DbgPrint("Got port handle %p, comm port handle %p\n", PortHandle, (PVOID)CommPortHandle);

    while (TRUE) {
	PORT_MESSAGE PortMessage = { .TotalLength = sizeof(PORT_MESSAGE) };
	Status = NtRequestPort(CommPortHandle, &PortMessage, NULL);
	if (!NT_SUCCESS(Status)) {
	    goto out;
	}
    }

out:
    NtTerminateProcess(NtCurrentProcess(), Status);
}
