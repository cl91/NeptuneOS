#include <psxdllp.h>

VOID PsxExitProcess(INT Status)
{
    NtTerminateProcess(NtCurrentProcess(), Status);
}

NTSTATUS PsxConnectPort(OUT PHANDLE CommPortHandle)
{
    ULONG MaxMessageLength = 0;
    SECURITY_QUALITY_OF_SERVICE SecurityQos;
    return NtConnectPortA(CommPortHandle, "\\PsxssApi", &SecurityQos,
			  NULL, NULL, NULL, &MaxMessageLength, NULL, 0);
}

VOID PsxProcessStartup()
{
    NtDisplayStringA("Hello from POSIX process\n");
    PPEB Peb = NtCurrentPeb();
    Peb->SyscallTable.ExitProcess = PsxExitProcess;

    HANDLE CommPortHandle = NULL;
    NTSTATUS Status = PsxConnectPort(&CommPortHandle);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }
    DbgPrint("Got comm port handle %p\n", CommPortHandle);

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
