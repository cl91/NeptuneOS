#include "psp.h"
#include <icif.h>

/*
 * Process Information Classes
 *
 * IMPORTANT: This must match the enum PROCESSINFOCLASS in ntpsapi.h
 */
static const INFORMATION_CLASS_INFO PsProcessInfoClass[] = {
    /* ProcessBasicInformation */
    IQS_SAME(PROCESS_BASIC_INFORMATION,
	     ULONG,
	     ICIF_QUERY),

    /* ProcessQuotaLimits */
    IQS_SAME(QUOTA_LIMITS,
	     ULONG,
	     ICIF_QUERY | ICIF_SET | ICIF_SET_SIZE_VARIABLE),

    /* ProcessIoCounters */
    IQS_SAME(IO_COUNTERS,
	     ULONG,
	     ICIF_QUERY),

    /* ProcessVmCounters */
    IQS_SAME(VM_COUNTERS,
	     ULONG,
	     ICIF_QUERY | ICIF_QUERY_SIZE_VARIABLE),

    /* ProcessTimes */
    IQS_SAME(KERNEL_USER_TIMES,
	     ULONG,
	     ICIF_QUERY),

    /* ProcessBasePriority */
    IQS_SAME(KPRIORITY,
	     ULONG,
	     ICIF_SET),

    /* ProcessRaisePriority */
    IQS_SAME(ULONG,
	     ULONG,
	     ICIF_SET),

    /* ProcessDebugPort */
    IQS_SAME(HANDLE,
	     ULONG,
	     ICIF_QUERY),

    /* ProcessExceptionPort */
    IQS_SAME(HANDLE,
	     ULONG,
	     ICIF_SET),

    /* ProcessAccessToken */
    IQS_SAME(PROCESS_ACCESS_TOKEN,
	     ULONG,
	     ICIF_SET),

    /* ProcessLdtInformation */
    IQS_SAME(PROCESS_LDT_INFORMATION,
	     ULONG,
	     ICIF_QUERY | ICIF_SET),

    /* ProcessLdtSize */
    IQS_SAME(PROCESS_LDT_SIZE,
	     ULONG,
	     ICIF_SET),

    /* ProcessDefaultHardErrorMode */
    IQS_SAME(ULONG,
	     ULONG,
	     ICIF_QUERY | ICIF_SET),

    /* ProcessIoPortHandlers */
    IQS_SAME(UCHAR,
	     ULONG,
	     ICIF_SET),

    /* ProcessPooledUsageAndLimits */
    IQS_SAME(POOLED_USAGE_AND_LIMITS,
	     ULONG,
	     ICIF_QUERY),

    /* ProcessWorkingSetWatch */
    IQS_SAME(PROCESS_WS_WATCH_INFORMATION,
	     ULONG,
	     ICIF_QUERY | ICIF_SET | ICIF_SET_SIZE_VARIABLE),

    /* ProcessUserModeIOPL is only implemented in x86 */
#if defined (_X86_)
    IQS_NO_TYPE_LENGTH(ULONG,
		       ICIF_SET),
#else
    IQS_NONE,
#endif

    /* ProcessEnableAlignmentFaultFixup */
    IQS(BOOLEAN,
	CHAR,
	BOOLEAN,
	CHAR,
	ICIF_SET),

    /* ProcessPriorityClass */
    IQS(PROCESS_PRIORITY_CLASS,
	ULONG,
	PROCESS_PRIORITY_CLASS,
	CHAR,
	ICIF_QUERY | ICIF_SET),

    /* ProcessWx86Information */
    IQS_SAME(ULONG,
	     ULONG,
	     ICIF_QUERY | ICIF_SET),

    /* ProcessHandleCount */
    IQS_SAME(ULONG,
	     ULONG,
	     ICIF_QUERY),

    /* ProcessAffinityMask */
    IQS_SAME(KAFFINITY,
	     ULONG,
	     ICIF_SET),

    /* ProcessPriorityBoost */
    IQS_SAME(ULONG,
	     ULONG,
	     ICIF_QUERY | ICIF_SET),

    /* ProcessDeviceMap */
    IQS(RTL_FIELD_TYPE(PROCESS_DEVICEMAP_INFORMATION, Query),
	ULONG,
	RTL_FIELD_TYPE(PROCESS_DEVICEMAP_INFORMATION, Set),
	ULONG,
	ICIF_QUERY | ICIF_SET),

    /* ProcessSessionInformation */
    IQS_SAME(PROCESS_SESSION_INFORMATION,
	     ULONG,
	     ICIF_QUERY | ICIF_SET),

    /* ProcessForegroundInformation */
    IQS(CHAR,
	CHAR,
	BOOLEAN,
	CHAR,
	ICIF_SET),

    /* ProcessWow64Information */
    IQS_SAME(ULONG_PTR,
	     ULONG,
	     ICIF_QUERY),

    /* ProcessImageFileName */
    IQS_SAME(UNICODE_STRING,
	     ULONG,
	     ICIF_QUERY | ICIF_QUERY_SIZE_VARIABLE),

    /* ProcessLUIDDeviceMapsEnabled */
    IQS_SAME(ULONG,
	     ULONG,
	     ICIF_QUERY),

    /* ProcessBreakOnTermination */
    IQS_SAME(ULONG,
	     ULONG,
	     ICIF_QUERY | ICIF_SET),

    /* ProcessDebugObjectHandle */
    IQS_SAME(HANDLE,
	     ULONG,
	     ICIF_QUERY),

    /* ProcessDebugFlags */
    IQS_SAME(ULONG,
	     ULONG,
	     ICIF_QUERY | ICIF_SET),

    /* ProcessHandleTracing */
    IQS(PROCESS_HANDLE_TRACING_QUERY,
	ULONG,
	ULONG,
	ULONG,
	ICIF_QUERY | ICIF_SET),

    /* ProcessIoPriority */
    IQS_NONE,

    /* ProcessExecuteFlags */
    IQS_SAME(ULONG,
	     ULONG,
	     ICIF_QUERY | ICIF_SET),

    /* ProcessTlsInformation */
    IQS_NONE,

    /* ProcessCookie */
    IQS_SAME(ULONG,
	     ULONG,
	     ICIF_QUERY),

    /* ProcessImageInformation */
    IQS_SAME(SECTION_IMAGE_INFORMATION,
	     ULONG,
	     ICIF_QUERY),

    /* ProcessCycleTime */
    IQS_NONE,

    /* ProcessPagePriority */
    IQS_NONE,

    /* ProcessInstrumentationCallback */
    IQS_NONE,

    /* ProcessThreadStackAllocation */
    IQS_NONE,

    /* ProcessWorkingSetWatchEx */
    IQS_NONE,

    /* ProcessImageFileNameWin32 */
    IQS_SAME(CHAR,
	     CHAR,
	     ICIF_NONE),

    /* ProcessImageFileMapping */
    IQS_NONE,

    /* ProcessAffinityUpdateMode */
    IQS_NONE,

    /* ProcessMemoryAllocationMode */
    IQS_NONE,
};

/*
 * Thread Information Classes
 *
 * IMPORTANT: This must match the enum THREADINFOCLASS in ntpsapi.h
 */
static const INFORMATION_CLASS_INFO PsThreadInfoClass[] = {
    /* ThreadBasicInformation */
    IQS_SAME(THREAD_BASIC_INFORMATION,
	     ULONG,
	     ICIF_QUERY),

    /* ThreadTimes */
    IQS_SAME(KERNEL_USER_TIMES,
	     ULONG,
	     ICIF_QUERY),

    /* ThreadPriority */
    IQS_SAME(KPRIORITY,
	     ULONG,
	     ICIF_SET),

    /* ThreadBasePriority */
    IQS_SAME(LONG,
	     ULONG,
	     ICIF_SET),

    /* ThreadAffinityMask */
    IQS_SAME(KAFFINITY,
	     ULONG,
	     ICIF_SET),

    /* ThreadImpersonationToken */
    IQS_SAME(HANDLE,
	     ULONG,
	     ICIF_SET),

    /* ThreadDescriptorTableEntry is only implemented in x86 as well as the descriptor entry */
#if defined(_X86_)
    IQS_SAME(DESCRIPTOR_TABLE_ENTRY,
	     ULONG,
	     ICIF_QUERY),
#else
    IQS_NONE,
#endif

    /* ThreadEnableAlignmentFaultFixup */
    IQS(CHAR,
	CHAR,
	BOOLEAN,
	UCHAR,
	ICIF_SET),

    /* ThreadEventPair_Reusable */
    IQS_NONE,

    /* ThreadQuerySetWin32StartAddress */
    IQS(PVOID,
	ULONG,
	ULONG_PTR,
	ULONG,
	ICIF_QUERY | ICIF_SET),

    /* ThreadZeroTlsCell */
    IQS_SAME(ULONG,
	     ULONG,
	     ICIF_SET),

    /* ThreadPerformanceCount */
    IQS_SAME(LARGE_INTEGER,
	     ULONG,
	     ICIF_QUERY),

    /* ThreadAmILastThread */
    IQS_SAME(ULONG,
	     ULONG,
	     ICIF_QUERY),

    /* ThreadIdealProcessor */
    IQS_SAME(ULONG_PTR,
	     ULONG,
	     ICIF_SET),

    /* ThreadPriorityBoost */
    IQS(ULONG,
	ULONG,
	ULONG_PTR,
	ULONG,
	ICIF_QUERY | ICIF_SET),

    /* ThreadSetTlsArrayAddress */
    IQS_SAME(PVOID,
	     ULONG,
	     ICIF_SET | ICIF_SIZE_VARIABLE),

    /* ThreadIsIoPending */
    IQS_SAME(ULONG,
	     ULONG,
	     ICIF_QUERY),

    /* ThreadHideFromDebugger */
    IQS_SAME(CHAR,
	     ULONG,
	     ICIF_SET | ICIF_SET_SIZE_VARIABLE),

    /* ThreadBreakOnTermination */
    IQS_SAME(ULONG,
	     ULONG,
	     ICIF_QUERY | ICIF_SET),

    /* ThreadSwitchLegacyState */
    IQS_SAME(ULONG,
	     ULONG,
	     ICIF_SET),

    /* ThreadIsTerminated */
    IQS_SAME(ULONG,
	     ULONG,
	     ICIF_QUERY),

    /* ThreadLastSystemCall */
    IQS_NONE,

    /* ThreadIoPriority */
    IQS_NONE,

    /* ThreadCycleTime */
    IQS_NONE,

    /* ThreadPagePriority */
    IQS_NONE,

    /* ThreadActualBasePriority */
    IQS_NONE,

    /* ThreadTebInformation */
    IQS_NONE,

    /* ThreadCSwitchMon */
    IQS_NONE,
};

static inline NTSTATUS DefaultQueryInfoBufferCheck(ULONG Class,
						   const INFORMATION_CLASS_INFO *ClassList,
						   ULONG ClassListEntries,
						   PVOID Buffer,
						   ULONG BufferLength,
						   ULONG OPTIONAL *Length)
{
    if (Class >= ClassListEntries) {
	return STATUS_INVALID_INFO_CLASS;
    }

    if (!(ClassList[Class].Flags & ICIF_QUERY)) {
	return STATUS_INVALID_INFO_CLASS;
    }

    if ((ClassList[Class].RequiredSizeQUERY > 0 &&
	 BufferLength != ClassList[Class].RequiredSizeQUERY)
	&& (!(ClassList[Class].Flags & ICIF_QUERY_SIZE_VARIABLE))) {
	return STATUS_INFO_LENGTH_MISMATCH;
    }

    if (Length) {
	*Length = ClassList[Class].RequiredSizeQUERY;
    }

    return STATUS_SUCCESS;
}

NTSTATUS NtQueryPerformanceCounter(IN ASYNC_STATE State,
				   IN PTHREAD Thread,
                                   OUT LARGE_INTEGER *PerformanceCounter,
                                   OUT OPTIONAL LARGE_INTEGER *PerformanceFrequency)
{
    UNIMPLEMENTED;
}

NTSTATUS NtQueryInformationProcess(IN ASYNC_STATE State,
				   IN PTHREAD Thread,
                                   IN HANDLE ProcessHandle,
                                   IN PROCESS_INFORMATION_CLASS ProcessInformationClass,
                                   IN PVOID ProcessInformation,
                                   IN ULONG ProcessInformationLength,
                                   OUT OPTIONAL ULONG *ReturnLength)
{
    /* Verify Information Class validity */
    ULONG Length;
    RET_ERR(DefaultQueryInfoBufferCheck(ProcessInformationClass,
					PsProcessInfoClass,
					RTL_NUMBER_OF(PsProcessInfoClass),
					ProcessInformation,
					ProcessInformationLength,
					&Length));

    if (((ProcessInformationClass == ProcessCookie) ||
	 (ProcessInformationClass == ProcessImageInformation)) &&
	(ProcessHandle != NtCurrentProcess())) {
	/*
	 * Retrieving the process cookie is only allowed for the calling process
	 * itself! XP only allows NtCurrentProcess() as process handles even if
	 * a real handle actually represents the current process.
	 */
	return STATUS_INVALID_PARAMETER;
    }

    PPROCESS Process = NULL;
    if (ProcessHandle == NtCurrentProcess()) {
	Process = Thread->Process;
    } else {
	RET_ERR(ObReferenceObjectByHandle(Thread->Process, ProcessHandle,
					  OBJECT_TYPE_PROCESS, (POBJECT *) &Process));
    }
    assert(Process != NULL);
    PVOID ProcessInformationMapped = NULL;
    NTSTATUS Status;
    IF_ERR_GOTO(out, Status, MmMapUserBuffer(&Thread->Process->VSpace,
					     (MWORD)ProcessInformation,
					     ProcessInformationLength,
					     &ProcessInformationMapped));

    /* Check the information class */
    Status = STATUS_SUCCESS;
    switch (ProcessInformationClass) {
    case ProcessBasicInformation:
    {
	/* Basic process information */
	PPROCESS_BASIC_INFORMATION ProcessBasicInfo = (PPROCESS_BASIC_INFORMATION)ProcessInformationMapped;
	ProcessBasicInfo->ExitStatus = Process->ExitStatus;
	ProcessBasicInfo->PebBaseAddress = (PPEB)Process->PebClientAddr;
	ProcessBasicInfo->AffinityMask = Process->AffinityMask;
	ProcessBasicInfo->UniqueProcessId = OBJECT_TO_GLOBAL_HANDLE(Process);
	ProcessBasicInfo->InheritedFromUniqueProcessId = Process->InheritedFromUniqueProcessId;
	ProcessBasicInfo->BasePriority = Process->BasePriority;
	break;
    }
#if 0
    case ProcessQuotaLimits:
	/* Process quota limits */
	PQUOTA_LIMITS QuotaLimits = (PQUOTA_LIMITS)ProcessInformationMapped;
	/* Set max/min working set sizes */
	QuotaLimits->MaximumWorkingSetSize = Process->Vm.MaximumWorkingSetSize << PAGE_SHIFT;
	QuotaLimits->MinimumWorkingSetSize = Process->Vm.MinimumWorkingSetSize << PAGE_SHIFT;
	/* Set default time limits */
	QuotaLimits->TimeLimit.LowPart = MAXULONG;
	QuotaLimits->TimeLimit.HighPart = MAXULONG;
	/* Is quota block a default one? */
	if (Process->QuotaBlock == &PspDefaultQuotaBlock) {
	    /* Set default pools and pagefile limits */
	    QuotaLimits->PagedPoolLimit = (SIZE_T) -1;
	    QuotaLimits->NonPagedPoolLimit = (SIZE_T) -1;
	    QuotaLimits->PagefileLimit = (SIZE_T) -1;
	} else {
	    /* Get limits from non-default quota block */
	    QuotaLimits->PagedPoolLimit = Process->QuotaBlock->QuotaEntry[PagedPool].Limit;
	    QuotaLimits->NonPagedPoolLimit = Process->QuotaBlock->QuotaEntry[NonPagedPool].Limit;
	    QuotaLimits->PagefileLimit = Process->QuotaBlock->QuotaEntry[2].Limit;
	}
	break;

    case ProcessIoCounters:
	PROCESS_VALUES ProcessValues;
	/* Query IO counters from the process */
	KeQueryValuesProcess(&Process->Pcb, &ProcessValues);
	RtlCopyMemory(ProcessInformationMapped, &ProcessValues.IoInfo,
		      sizeof(IO_COUNTERS));
	break;

    case ProcessTimes:
	/* Timing */
	PKERNEL_USER_TIMES ProcessTime = (PKERNEL_USER_TIMES)ProcessInformationMapped;
	ULONG UserTime;
	ULONG KernelTime = KeQueryRuntimeProcess(&Process->Pcb, &UserTime);
	ProcessTime->CreateTime = Process->CreateTime;
	ProcessTime->UserTime.QuadPart = ((LONGLONG)UserTime) * KeMaximumIncrement;
	ProcessTime->KernelTime.QuadPart = ((LONGLONG)KernelTime) * KeMaximumIncrement;
	ProcessTime->ExitTime = Process->ExitTime;
	break;

    case ProcessDebugPort:
	/* Return whether or not we have a process debug port */
	*(PHANDLE) ProcessInformationMapped = Process->DebugPort ? (HANDLE)-1 : NULL;
	break;

    case ProcessHandleCount:
	/* Count the number of handles this process has */
	ULONG HandleCount = ObGetProcessHandleCount(Process);
	*(PULONG) ProcessInformationMapped = HandleCount;
	break;

    case ProcessSessionInformation:
	/* Session ID for the process */
	PPROCESS_SESSION_INFORMATION SessionInfo = (PPROCESS_SESSION_INFORMATION)ProcessInformationMapped;
	/* Write back the Session ID */
	SessionInfo->SessionId = PsGetProcessSessionId(Process);
	break;

    case ProcessVmCounters:
	/* Virtual Memory Statistics */
	PVM_COUNTERS VmCounters = (PVM_COUNTERS)ProcessInformationMapped;
	/* Return data from PROCESS */
	VmCounters->PeakVirtualSize = Process->PeakVirtualSize;
	VmCounters->VirtualSize = Process->VirtualSize;
	VmCounters->PageFaultCount = Process->Vm.PageFaultCount;
	VmCounters->PeakWorkingSetSize = Process->Vm.PeakWorkingSetSize;
	VmCounters->WorkingSetSize = Process->Vm.WorkingSetSize;
	VmCounters->QuotaPeakPagedPoolUsage = Process->QuotaPeak[PsPagedPool];
	VmCounters->QuotaPagedPoolUsage = Process->QuotaUsage[PsPagedPool];
	VmCounters->QuotaPeakNonPagedPoolUsage = Process->QuotaPeak[PsNonPagedPool];
	VmCounters->QuotaNonPagedPoolUsage = Process->QuotaUsage[PsNonPagedPool];
	VmCounters->PagefileUsage = Process->QuotaUsage[PsPageFile] << PAGE_SHIFT;
	VmCounters->PeakPagefileUsage = Process->QuotaPeak[PsPageFile] << PAGE_SHIFT;
	//VmCounters->PrivateUsage = Process->CommitCharge << PAGE_SHIFT;
	break;

    case ProcessDefaultHardErrorMode:
	/* Hard Error Processing Mode */
	*(PULONG) ProcessInformationMapped = Process->DefaultHardErrorProcessing;
	break;

    case ProcessPriorityBoost:
	/* Priority Boosting status */
	*(PULONG) ProcessInformationMapped = Process->Pcb.DisableBoost ? TRUE : FALSE;
	break;

    case ProcessDeviceMap:
	/* DOS Device Map */
	if (ProcessInformationLength == sizeof(PROCESS_DEVICEMAP_INFORMATION_EX)) {
	    PPROCESS_DEVICEMAP_INFORMATION_EX DeviceMapEx = ProcessInformationMapped;
	    ULONG Flags = DeviceMapEx->Flags;
	    /* Only one flag is supported and it needs LUID mappings */
	    if ((Flags & ~PROCESS_LUID_DOSDEVICES_ONLY) != 0 || !ObIsLUIDDeviceMapsEnabled()) {
		Status = STATUS_INVALID_PARAMETER;
		break;
	    }
	} else {
	    /* This has to be the size of the Query union field for x64 compatibility! */
	    if (ProcessInformationLength != RTL_FIELD_SIZE(PROCESS_DEVICEMAP_INFORMATION, Query)) {
		Status = STATUS_INFO_LENGTH_MISMATCH;
		break;
	    }
	    /* No flags for standard call */
	    Flags = 0;
	}
	/* Set the return length */
	Length = ProcessInformationLength;
	/* Query the device map information */
	Status = ObQueryDeviceMapInformation(Process, ProcessInformationMapped, Flags);
	break;

    case ProcessPriorityClass:
	/* Priority class */
	PPROCESS_PRIORITY_CLASS PsPriorityClass = (PPROCESS_PRIORITY_CLASS)ProcessInformationMapped;
	/* Return current priority class */
	PsPriorityClass->PriorityClass = Process->PriorityClass;
	PsPriorityClass->Foreground = FALSE;
	break;

    case ProcessImageFileName:
	PUNICODE_STRING ImageName;
	/* Get the image path */
	Status = SeLocateProcessImageName(Process, &ImageName);
	if (NT_SUCCESS(Status)) {
	    /* Set return length */
	    Length = sizeof(OBJECT_NAME_INFORMATION) + ImageName->MaximumLength;

	    /* Make sure it's large enough */
	    if (Length <= ProcessInformationLength) {
		/* Copy it */
		RtlCopyMemory(ProcessInformationMapped, ImageName, Length);
		/* Update pointer. TODO: This must be converted to client pointer */
		/* FIXME!!! */
		//((POBJECT_NAME_INFORMATION)ProcessInformationMapped)->Buffer = 0;
	    } else {
		/* Buffer too small */
		Status = STATUS_INFO_LENGTH_MISMATCH;
	    }
	    /* Free the image path */
	    ExFreePool(ImageName);
	}
	break;

    case ProcessDebugFlags:
	/* Return the debug flag state */
	*(PULONG) ProcessInformationMapped = Process->NoDebugInherit ? 0 : 1;
	break;

    case ProcessBreakOnTermination:
	/* Return the BreakOnTermination state */
	*(PULONG) ProcessInformationMapped = Process->BreakOnTermination;
	break;
#endif

    case ProcessCookie:
	/* Per-process security cookie */
	*(PULONG) ProcessInformationMapped = Process->Cookie;
	break;

#if 0
    case ProcessImageInformation:
	MmGetImageInformation((PSECTION_IMAGE_INFORMATION)ProcessInformationMapped);
	break;

    case ProcessDebugObjectHandle:
	/* Get the debug port */
	HANDLE DebugPort = 0;
	Status = DbgkOpenProcessDebugPort(Process, &DebugPort);
	/* Return debug port's handle */
	*(PHANDLE) ProcessInformationMapped = DebugPort;
	break;

    case ProcessHandleTracing:
	DPRINT1("Handle tracing Not implemented: %lx\n",
		ProcessInformationClass);
	UNIMPLEMENTED_ROUTINE;
	Status = STATUS_NOT_IMPLEMENTED;
	break;

    case ProcessLUIDDeviceMapsEnabled:
	/* Query Ob */
	*(PULONG) ProcessInformationMapped = ObIsLUIDDeviceMapsEnabled();
	break;

    case ProcessWx86Information:
	/* Return if the flag is set */
	*(PULONG) ProcessInformationMapped = (ULONG) Process->VdmAllowed;
	break;

    case ProcessWow64Information:
	/* Get the WOW64 process structure */
	ULONG_PTR Wow64 = 0;
#ifdef _WIN64
	Wow64 = (ULONG_PTR) Process->Wow64Process;
#else
	Wow64 = 0;
#endif
	*(PULONG_PTR) ProcessInformationMapped = Wow64;
	break;

    case ProcessExecuteFlags:
	/* Get the options */
	ULONG ExecuteOptions = 0
	Status = MmGetExecuteOptions(&ExecuteOptions);
	*(PULONG) ProcessInformationMapped = ExecuteOptions;
	break;
#endif

    case ProcessLdtInformation:
	DPRINT1("VDM/16-bit not implemented: %x\n",
		ProcessInformationClass);
	UNIMPLEMENTED_ROUTINE;
	Status = STATUS_NOT_IMPLEMENTED;
	break;

    case ProcessWorkingSetWatch:
	DPRINT1("WS Watch Not implemented: %x\n",
		ProcessInformationClass);
	UNIMPLEMENTED_ROUTINE;
	Status = STATUS_NOT_IMPLEMENTED;
	break;

    case ProcessPooledUsageAndLimits:
	DPRINT1("Pool limits Not implemented: %x\n",
		ProcessInformationClass);
	UNIMPLEMENTED_ROUTINE;
	Status = STATUS_NOT_IMPLEMENTED;
	break;

    default:
	UNIMPLEMENTED_ROUTINE;
	Status = STATUS_NOT_IMPLEMENTED;
    }

out:
    if (ProcessInformationMapped != NULL) {
	MmUnmapUserBuffer(ProcessInformationMapped);
    }
    if (ProcessHandle != NtCurrentProcess()) {
	ObDereferenceObject(Process);
    }
    if ((ReturnLength) && (Length)) {
	*ReturnLength = Length;
    }
    return Status;
}

NTSTATUS NtQueryInformationThread(IN ASYNC_STATE State,
				  IN PTHREAD Thread,
                                  IN HANDLE ThreadHandle,
                                  IN THREAD_INFORMATION_CLASS ThreadInformationClass,
                                  IN PVOID ThreadInformationBuffer,
                                  IN ULONG ThreadInformationLength,
                                  OUT OPTIONAL ULONG *ReturnLength)
{
    UNIMPLEMENTED;
}

NTSTATUS NtSetInformationProcess(IN ASYNC_STATE State,
				 IN PTHREAD Thread,
                                 IN HANDLE ProcessHandle,
                                 IN PROCESS_INFORMATION_CLASS ProcessInformationClass,
                                 IN PVOID ProcessInformationBuffer,
                                 IN ULONG ProcessInformationLength)
{
    UNIMPLEMENTED;
}

NTSTATUS NtSetInformationThread(IN ASYNC_STATE State,
				IN PTHREAD Thread,
                                IN HANDLE ThreadHandle,
                                IN THREAD_INFORMATION_CLASS ThreadInformationClass,
                                IN PVOID ThreadInformationBuffer,
                                IN ULONG ThreadInformationLength)
{
    UNIMPLEMENTED;
}
