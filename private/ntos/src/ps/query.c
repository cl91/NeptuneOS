#include "psp.h"

NTSTATUS NtQuerySystemInformation(IN PTHREAD Thread,
                                  IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
                                  IN PVOID SystemInformationBuffer,
                                  IN ULONG SystemInformationLength,
                                  OUT OPTIONAL ULONG *ReturnLength)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtQueryPerformanceCounter(IN PTHREAD Thread,
                                   OUT LARGE_INTEGER *PerformanceCounter,
                                   OUT OPTIONAL LARGE_INTEGER *PerformanceFrequency)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtQueryInformationProcess(IN PTHREAD Thread,
                                   IN HANDLE ProcessHandle,
                                   IN PROCESS_INFORMATION_CLASS ProcessInformationClass,
                                   IN PVOID ProcessInformationBuffer,
                                   IN ULONG ProcessInformationLength,
                                   OUT OPTIONAL ULONG *ReturnLength)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtQueryInformationThread(IN PTHREAD Thread,
                                  IN HANDLE ThreadHandle,
                                  IN THREAD_INFORMATION_CLASS ThreadInformationClass,
                                  IN PVOID ThreadInformationBuffer,
                                  IN ULONG ThreadInformationLength,
                                  OUT OPTIONAL ULONG *ReturnLength)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtSetInformationProcess(IN PTHREAD Thread,
                                 IN HANDLE ProcessHandle,
                                 IN PROCESS_INFORMATION_CLASS ProcessInformationClass,
                                 IN PVOID ProcessInformationBuffer,
                                 IN ULONG ProcessInformationLength)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtSetInformationThread(IN PTHREAD Thread,
                                IN HANDLE ThreadHandle,
                                IN THREAD_INFORMATION_CLASS ThreadInformationClass,
                                IN PVOID ThreadInformationBuffer,
                                IN ULONG ThreadInformationLength)
{
    return STATUS_NOT_IMPLEMENTED;
}