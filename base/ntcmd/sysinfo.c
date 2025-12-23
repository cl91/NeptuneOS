/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Module Name:

    sysinfo.c

Abstract:

    The Native Command Line Interface is the command shell for Neptune OS.
    This module implements commands for displaying system information.

Environment:

    Native mode

Revision History:

    Alex Ionescu - Started Implementation - 23-Mar-06

--*/
#include "ntcmd.h"

/*++
 * @name RtlCliShutdown
 *
 * The RtlCliShutdown routine FILLMEIN
 *
 * @param None.
 *
 * @return NTSTATUS
 *
 * @remarks Documentation for this routine needs to be completed.
 *
 *--*/
NTSTATUS RtlCliShutdown(VOID)
{
    BOOLEAN Old;

    //
    // Get the shutdown privilege and shutdown the system
    //
    RtlAdjustPrivilege(SE_SHUTDOWN_PRIVILEGE, TRUE, FALSE, &Old);
    return NtShutdownSystem(ShutdownNoReboot);
}

/*++
 * @name RtlCliReboot
 *
 * The RtlCliReboot routine FILLMEIN
 *
 * @param None.
 *
 * @return NTSTATUS
 *
 * @remarks Documentation for this routine needs to be completed.
 *
 *--*/
NTSTATUS RtlCliReboot(VOID)
{
    BOOLEAN Old;

    //
    // Get the shutdown privilege and shutdown the system
    //
    RtlAdjustPrivilege(SE_SHUTDOWN_PRIVILEGE, TRUE, FALSE, &Old);
    return NtShutdownSystem(ShutdownReboot);
}

/*++
 * @name RtlCliPowerOff
 *
 * The RtlCliPowerOff routine FILLMEIN
 *
 * @param None.
 *
 * @return NTSTATUS
 *
 * @remarks Documentation for this routine needs to be completed.
 *
 *--*/
NTSTATUS RtlCliPowerOff(VOID)
{
    BOOLEAN Old;

    //
    // Get the shutdown privilege and shutdown the system
    //
    RtlAdjustPrivilege(SE_SHUTDOWN_PRIVILEGE, TRUE, FALSE, &Old);
    return NtShutdownSystem(ShutdownPowerOff);
}

/*++
 * @name RtlCliListDrivers
 *
 * The RtlCliListDrivers routine FILLMEIN
 *
 * @param None.
 *
 * @return NTSTATUS
 *
 * @remarks Documentation for this routine needs to be completed.
 *
 *--*/
NTSTATUS RtlCliListDrivers(VOID)
{
    PRTL_PROCESS_MODULES ModuleInfo;
    PRTL_PROCESS_MODULE_INFORMATION ModuleEntry;
    ULONG Size = 0;

    //
    // Get the count first
    //
    NTSTATUS Status = NtQuerySystemInformation(SystemModuleInformation,
					       &Size, sizeof(Size), NULL);
    if (!NT_SUCCESS(Status)) {
        RtlCliDisplayString("NtQuerySystemInformation failed with error 0x%08x\n",
			    Status);
	return Status;
    }

    if (!Size) {
	RtlCliDisplayString("No active driver loaded.\n");
	return STATUS_SUCCESS;
    }

    //
    // Get the total buffer size
    //
    Size = FIELD_OFFSET(RTL_PROCESS_MODULES, Modules) +
	Size * sizeof(RTL_PROCESS_MODULE_INFORMATION);

    //
    // Allocate it
    //
    ModuleInfo = RtlAllocateHeap(RtlGetProcessHeap(), 0, Size);

    //
    // Query the buffer
    //
    Status = NtQuerySystemInformation(SystemModuleInformation,
				      ModuleInfo, Size, NULL);

    if (!NT_SUCCESS(Status)) {
        RtlCliDisplayString("NtQuerySystemInformation failed with error 0x%08x\n",
			    Status);
	goto out;
    }

    //
    // Display Header
    //
    RtlCliDisplayString("List of driver objects (%d total):\n",
			ModuleInfo->NumberOfModules);

    //
    // Now walk every module in it
    //
    for (ULONG i = 0; i < ModuleInfo->NumberOfModules; i++) {
	//
	// Check if we've displayed 20
	// BUGBUG: Should be natively handled by our display routines
	//

	if (i && !(i % (ConsoleMaxRows - 2))) {
	    //
	    // Hold for more input
	    //
	    RtlCliDisplayString("--- PRESS SPACE TO CONTINUE ---");
	    while (RtlCliGetChar(hKeyboard) != ' ');
	    RtlCliDisplayString("\n");
	}

	//
	// Get this entry
	//
	ModuleEntry = &ModuleInfo->Modules[i];

	//
	// Display basic data
	//
	RtlCliDisplayString("  %s - Base: %p Size: 0x%lx\n",
			    ModuleEntry->FullPathName,
			    ModuleEntry->MappedBase,
			    ModuleEntry->ImageSize);
    }

out:
    RtlFreeHeap(RtlGetProcessHeap(), 0, ModuleInfo);
    return Status;
}

/*++
 * @name RtlCliListProcesses
 *
 * The RtlCliListProcesses routine provides a way to list the current
 * processes.
 *
 * @param None.
 *
 * @return NTSTATUS
 *
 * @remarks Documentation for this routine needs to be completed.
 *
 *--*/
NTSTATUS RtlCliListProcesses(VOID)
{
    PSYSTEM_PROCESS_INFORMATION ModuleInfo;
    NTSTATUS Status;
    ULONG Size = 0x10000;

    //
    // Allocate a static buffer that should be large enough
    //
    ModuleInfo = RtlAllocateHeap(RtlGetProcessHeap(), 0, Size);
    if (!ModuleInfo)
	return STATUS_INSUFFICIENT_RESOURCES;

    //
    // Query the buffer
    //
    Status = NtQuerySystemInformation(SystemProcessInformation,
				      ModuleInfo, Size, NULL);
    if (!NT_SUCCESS(Status)) {
        RtlCliDisplayString("NtQuerySystemInformation failed with error 0x%08x\n",
			    Status);
	return Status;
    }

    //
    // Display Header
    //
    RtlCliDisplayString("List of process objects:\n");

    //
    // Now walk every module in it
    //
    while (TRUE) {
	//
	// ModuleInfo->ImageName.Buffer is a relative offset so we need to adjust it
	//
	ModuleInfo->ImageName.Buffer = (PVOID)((ULONG_PTR)ModuleInfo->ImageName.Buffer +
					       (ULONG_PTR)ModuleInfo);
	//
	// Display basic data
	//
	RtlCliDisplayString("  [%p] %ws - WS/PF/V:[%zdK/%zdK/%zdK] Threads: %d\n",
			    ModuleInfo->UniqueProcessId,
			    ModuleInfo->ImageName.Buffer,
			    ModuleInfo->WorkingSetSize / 1024,
			    ModuleInfo->PagefileUsage / 1024,
			    ModuleInfo->VirtualSize / 1024,
			    ModuleInfo->NumberOfThreads);

	//
	// Break out if we're done
	//
	if (!ModuleInfo->NextEntryOffset)
	    break;

	//
	// Get next entry
	//
	ModuleInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)ModuleInfo +
						   ModuleInfo->NextEntryOffset);
    }

    //
    // Return error code
    //
    return Status;
}

/*++
 * @name RtlCliDumpSysInfo
 *
 * The RtlCliDumpSysInfo routine queries a large amount of system information
 * and displays it on screen.
 *
 * @param None.
 *
 * @return NTSTATUS
 *
 * @remarks Documentation for this routine needs to be completed.
 *
 *--*/
NTSTATUS RtlCliDumpSysInfo(VOID)
{
    NTSTATUS Status;
    SYSTEM_BASIC_INFORMATION BasicInfo;
    SYSTEM_PROCESSOR_INFORMATION ProcInfo;
    SYSTEM_PERFORMANCE_INFORMATION PerfInfo;
    SYSTEM_TIMEOFDAY_INFORMATION TimeInfo;
    SYSTEM_FILECACHE_INFORMATION CacheInfo;
    PKUSER_SHARED_DATA SharedData = (PKUSER_SHARED_DATA) USER_SHARED_DATA;
    TIME_FIELDS BootTime, IdleTime, KernelTime, UserTime, DpcTime;

    //
    // Query basic system information
    //
    Status = NtQuerySystemInformation(SystemBasicInformation,
				      &BasicInfo, sizeof(BasicInfo), NULL);
    if (!NT_SUCCESS(Status)) {
	RtlCliDisplayString("NtQuerySystemInformation failed with error 0x%08x\n",
			    Status);
	return Status;
    }

    //
    // Query basic processor information
    //
    Status = NtQuerySystemInformation(SystemProcessorInformation,
				      &ProcInfo, sizeof(ProcInfo), NULL);
    if (!NT_SUCCESS(Status)) {
	RtlCliDisplayString("NtQuerySystemInformation failed with error 0x%08x\n",
			    Status);
	return Status;
    }

    //
    // Query basic system information
    //
    Status = NtQuerySystemInformation(SystemPerformanceInformation,
				      &PerfInfo, sizeof(PerfInfo), NULL);
    if (!NT_SUCCESS(Status)) {
	RtlCliDisplayString("NtQuerySystemInformation failed with error 0x%08x\n",
			    Status);
	return Status;
    }

    //
    // Query basic system information
    //
    Status = NtQuerySystemInformation(SystemTimeOfDayInformation,
				      &TimeInfo, sizeof(TimeInfo), NULL);
    if (!NT_SUCCESS(Status)) {
	RtlCliDisplayString("NtQuerySystemInformation failed with error 0x%08x\n",
			    Status);
	return Status;
    }

    //
    // Query basic system information
    //
    ULONG ProcPerfSize =
	BasicInfo.NumberOfProcessors * sizeof(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION);
    PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION ProcPerfInfo =
	RtlAllocateHeap(RtlGetProcessHeap(), 0, ProcPerfSize);
    if (!ProcPerfInfo) {
	RtlCliDisplayString("No memory.\n");
	return STATUS_NO_MEMORY;
    }
    Status = NtQuerySystemInformation(SystemProcessorPerformanceInformation,
				      ProcPerfInfo, ProcPerfSize, NULL);
    if (!NT_SUCCESS(Status)) {
	RtlCliDisplayString("NtQuerySystemInformation failed with error 0x%08x\n",
			    Status);
	return Status;
    }

    //
    // Query basic system information
    //
    Status = NtQuerySystemInformation(SystemFileCacheInformation,
				      &CacheInfo, sizeof(CacheInfo), NULL);
    if (!NT_SUCCESS(Status)) {
	RtlCliDisplayString("NtQuerySystemInformation failed with error 0x%08x\n",
			    Status);
	goto out;
    }

    //
    // Display Header
    //
    RtlTimeToTimeFields(&TimeInfo.BootTime, &BootTime);
    RtlCliDisplayString("System root is %ws. System booted on %02d-%02d-%02d "
			"at %02d:%02d.\n", SharedData->NtSystemRoot,
			BootTime.Day, BootTime.Month, BootTime.Year, BootTime.Hour,
			BootTime.Minute);

    //
    // Display System Flags
    //
    RtlCliDisplayString("Version: %x.%x. Debug Mode: %x. Safe Mode: %x "
			"Product Type: %x. Suite Mask: %x\n",
			SharedData->NtMajorVersion,
			SharedData->NtMinorVersion,
			SharedData->KdDebuggerEnabled,
			SharedData->SafeBootMode,
			SharedData->NtProductType, SharedData->SuiteMask);
    RtlCliDisplayString("-------------------------------------"
			"-------------------------------------\n");

    //
    // Display CPU Information
    //
    PCSTR ProcessorArchitecture = "Unknown";
    if (ProcInfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
	ProcessorArchitecture = "x86";
    } else if (ProcInfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
	ProcessorArchitecture = "amd64";
    }
    RtlCliDisplayString("[CPU] %d CPU(s). %s Family %d Model %x Stepping %x. "
			"Feature Bits: 0x%X NX: 0x%x.\n",
			BasicInfo.NumberOfProcessors,
			ProcessorArchitecture,
			ProcInfo.ProcessorLevel,
			ProcInfo.ProcessorRevision >> 8,
			ProcInfo.ProcessorRevision & 0xFF,
			ProcInfo.ProcessorFeatureBits,
			SharedData->NXSupportPolicy);

    //
    // Display RAM Information
    //
    RtlCliDisplayString("[RAM] Page Size: %dKB. Physical Pages: 0x%X. "
			"Total Physical RAM: %lldKB\n",
			BasicInfo.PageSize / 1024,
			BasicInfo.NumberOfPhysicalPages,
			(ULONG64)BasicInfo.NumberOfPhysicalPages * PAGE_SIZE / 1024);

    //
    // Display User-Mode Virtual Memory Information
    //
    RtlCliDisplayString("[USR] User-Mode Range: 0x%08zX-0x%zX. "
			"Allocation Granularity: %dKB\n",
			BasicInfo.MinimumUserModeAddress,
			BasicInfo.MaximumUserModeAddress,
			BasicInfo.AllocationGranularity / 1024);

    //
    // Display System Virtual Memory Information
    //
    RtlCliDisplayString("[VRAM] Free: %dKB. Committed: %dKB. "
			"Total: %dKB. Peak: %dKB\n",
			PerfInfo.AvailablePages * PAGE_SIZE / 1024,
			PerfInfo.CommittedPages * PAGE_SIZE / 1024,
			PerfInfo.CommitLimit * PAGE_SIZE / 1024,
			PerfInfo.PeakCommitment * PAGE_SIZE / 1024);

    //
    // Display Kernel Memory/Pool Information
    //
    RtlCliDisplayString("[KRNL] Paged: %dKB. Non-Paged: %dKB. "
			"Drivers: %dKB Code: %dKB\n",
			PerfInfo.PagedPoolPages * PAGE_SIZE / 1024,
			PerfInfo.NonPagedPoolPages * PAGE_SIZE / 1024,
			PerfInfo.TotalSystemDriverPages * PAGE_SIZE / 1024,
			PerfInfo.TotalSystemCodePages * PAGE_SIZE / 1024);

    //
    // Check if we have two CPUs
    //
    if (BasicInfo.NumberOfProcessors > 1) {
	//
	// Handle two CPU case by adding all of CPU 2's times into CPU 1's
	// FIXME: This should be improved to support 2+ CPUs later
	//
	ProcPerfInfo[0].IdleTime.QuadPart +=
	    ProcPerfInfo[1].IdleTime.QuadPart;
	ProcPerfInfo[0].KernelTime.QuadPart +=
	    ProcPerfInfo[1].KernelTime.QuadPart;
	ProcPerfInfo[0].UserTime.QuadPart +=
	    ProcPerfInfo[1].UserTime.QuadPart;
	ProcPerfInfo[0].DpcTime.QuadPart +=
	    ProcPerfInfo[1].DpcTime.QuadPart;
	ProcPerfInfo[0].InterruptCount += ProcPerfInfo[1].InterruptCount;
    }
    //
    // Convert all 64-bit times into a readable format
    //
    RtlTimeToTimeFields(&ProcPerfInfo[0].IdleTime, &IdleTime);
    RtlTimeToTimeFields(&ProcPerfInfo[0].KernelTime, &KernelTime);
    RtlTimeToTimeFields(&ProcPerfInfo[0].UserTime, &UserTime);
    RtlTimeToTimeFields(&ProcPerfInfo[0].DpcTime, &DpcTime);

    //
    // Display System Times
    //
    RtlCliDisplayString
	("[TIME] Kernel: %02d:%02d:%02d. User: %02d:%02d:%02d. "
	 "DPC: %02d:%02d:%02d. Idle: %02d:%02d:%02d.\n", KernelTime.Hour,
	 KernelTime.Minute, KernelTime.Second, UserTime.Hour,
	 UserTime.Minute, UserTime.Second, DpcTime.Hour, DpcTime.Minute,
	 DpcTime.Second, IdleTime.Hour, IdleTime.Minute, IdleTime.Second);

    //
    // Display Core Performance Information
    //
    RtlCliDisplayString("[PERF] INTs: %d. SysCalls: %d. PFs: %d. "
			"Ctx Switches: %d\n",
			ProcPerfInfo[0].InterruptCount,
			PerfInfo.SystemCalls,
			PerfInfo.PageFaultCount, PerfInfo.ContextSwitches);

    //
    // Display I/O Information
    //
    RtlCliDisplayString("[I/O] Reads: %d/%lldKB. Writes: %d/%lldKB. "
			"Others: %d/%lldKB\n",
			PerfInfo.IoReadOperationCount,
			PerfInfo.IoReadTransferCount.QuadPart / 1024,
			PerfInfo.IoWriteOperationCount,
			PerfInfo.IoWriteTransferCount.QuadPart / 1024,
			PerfInfo.IoOtherOperationCount,
			PerfInfo.IoOtherTransferCount.QuadPart / 1024);

    //
    // Display FileSystem Cache Information
    //
    RtlCliDisplayString("[CACHE] Size: %dKB. Peak: %dKB. "
			"Min WS: %dKB. Max WS: %dKB\n",
			CacheInfo.CurrentSize / 1024,
			CacheInfo.PeakSize / 1024,
			CacheInfo.MinimumWorkingSet,
			CacheInfo.MaximumWorkingSet);

    //
    // Return success
    //
    Status = STATUS_SUCCESS;
out:
    RtlFreeHeap(RtlGetProcessHeap(), 0, ProcPerfInfo);
    return Status;
}
