#include "ei.h"

/* --- Query/Set System Information --- */

/*
 * NOTE: QSI_DEF(n) and SSI_DEF(n) define _cdecl function symbols
 * so the stack is popped only in one place on x86 platform.
 */
#define QSI_USE(n) QSI##n
#define QSI_DEF(n) \
static NTSTATUS QSI_USE(n) (PVOID Buffer, ULONG Size, PULONG ReqSize)

#define SSI_USE(n) SSI##n
#define SSI_DEF(n) \
static NTSTATUS SSI_USE(n) (PVOID Buffer, ULONG Size)

/* Class 0 - Basic Information */
QSI_DEF(SystemBasicInformation)
{
    PSYSTEM_BASIC_INFORMATION Sbi = (PSYSTEM_BASIC_INFORMATION) Buffer;

    *ReqSize = sizeof(SYSTEM_BASIC_INFORMATION);

    /* Check user buffer's size */
    if (Size != sizeof(SYSTEM_BASIC_INFORMATION)) {
	return STATUS_INFO_LENGTH_MISMATCH;
    }

    RtlZeroMemory(Sbi, Size);
    Sbi->Reserved = 0;
    Sbi->TimerResolution = TIMER_RESOLUTION_IN_100NS;
    Sbi->PageSize = PAGE_SIZE;
    Sbi->NumberOfPhysicalPages = MmNumberOfPhysicalPages;
    Sbi->LowestPhysicalPageNumber = MmLowestPhysicalPage >> PAGE_LOG2SIZE;
    Sbi->HighestPhysicalPageNumber = MmHighestPhysicalPage >> PAGE_LOG2SIZE;
    Sbi->AllocationGranularity = PAGE_SIZE;
    Sbi->MinimumUserModeAddress = LOWEST_USER_ADDRESS;
    Sbi->MaximumUserModeAddress = HIGHEST_USER_ADDRESS;
    Sbi->ActiveProcessorsAffinityMask = 0;
    Sbi->NumberOfProcessors = KeProcessorCount;

    return STATUS_SUCCESS;
}

/* Class 1 - Processor Information */
QSI_DEF(SystemProcessorInformation)
{
    PSYSTEM_PROCESSOR_INFORMATION Spi = (PSYSTEM_PROCESSOR_INFORMATION)Buffer;

    *ReqSize = sizeof(SYSTEM_PROCESSOR_INFORMATION);

    /* Check user buffer's size */
    if (Size != sizeof(SYSTEM_PROCESSOR_INFORMATION)) {
	return STATUS_INFO_LENGTH_MISMATCH;
    }

    RtlZeroMemory(Spi, Size);
    Spi->ProcessorArchitecture = KeProcessorArchitecture;
    Spi->ProcessorLevel = KeProcessorLevel;
    Spi->ProcessorRevision = KeProcessorRevision;
    Spi->MaximumProcessors = 0;
    Spi->ProcessorFeatureBits = KeFeatureBits;
    return STATUS_SUCCESS;
}

/* Class 3 - Time Of Day Information */
QSI_DEF(SystemTimeOfDayInformation)
{
    SYSTEM_TIMEOFDAY_INFORMATION Sti;
    LARGE_INTEGER CurrentTime;

    /* Set amount of written information to 0 */
    *ReqSize = 0;

    /* Check user buffer's size */
    if (Size > sizeof(SYSTEM_TIMEOFDAY_INFORMATION)) {
	return STATUS_INFO_LENGTH_MISMATCH;
    }

    /* Get current time */
    CurrentTime.QuadPart = KeQuerySystemTime();

    /* Zero local buffer */
    RtlZeroMemory(&Sti, sizeof(SYSTEM_TIMEOFDAY_INFORMATION));

    /* Fill local time structure */
    Sti.BootTime.QuadPart = 0;		/* TODO */
    Sti.CurrentTime = CurrentTime;
    Sti.TimeZoneBias.QuadPart = 0; /* TODO */
    Sti.TimeZoneId = 0;		   /* TODO */
    Sti.Reserved = 0;

    /* Copy as much as requested by caller */
    RtlCopyMemory(Buffer, &Sti, Size);

    /* Set amount of information we copied */
    *ReqSize = Size;

    return STATUS_SUCCESS;
}

/* Class 5 - Process Information */
QSI_DEF(SystemProcessInformation)
{
    ULONG TotalSize = 0;

    *ReqSize = sizeof(SYSTEM_PROCESS_INFORMATION);

    if (Size < sizeof(SYSTEM_PROCESS_INFORMATION)) {
	return STATUS_INFO_LENGTH_MISMATCH;
    }

    RtlZeroMemory(Buffer, Size);

    /* Scan the process list */
    PSYSTEM_PROCESS_INFORMATION Spi = Buffer;
    PUCHAR Current = (PUCHAR)Spi;
    PSYSTEM_PROCESS_INFORMATION SpiCurrent = NULL;
    BOOLEAN Overflow = FALSE;
    extern LIST_ENTRY PspProcessList;
    LoopOverList(Process, &PspProcessList, PROCESS, ProcessListEntry) {
	SpiCurrent = (PSYSTEM_PROCESS_INFORMATION)Current;

	if (!Process->Initialized) {
	    DbgTrace("Process %p (%s) is a zombie, skipping\n", Process,
		     KEDBG_PROCESS_TO_FILENAME(Process));
	    continue;
	}

	ULONG ThreadCount = GetListLength(&Process->ThreadList);
	ULONG CurrentSize = sizeof(SYSTEM_PROCESS_INFORMATION) +
	    sizeof(SYSTEM_THREAD_INFORMATION) * ThreadCount;
	PCSTR ImageName = KEDBG_PROCESS_TO_FILENAME(Process);
	ULONG ImageNameLength = 0;
	RtlUTF8ToUnicodeN(NULL, ULONG_MAX, &ImageNameLength, ImageName, strlen(ImageName));
	/* Round up the image name length as NT does */
	ULONG ImageNameMaximumLength = 0;
	if (ImageNameLength) {
	    ImageNameMaximumLength = ALIGN_UP_BY(ImageNameLength + sizeof(WCHAR), 8);
	}

	TotalSize += CurrentSize + ImageNameMaximumLength;

	/* Check for overflow */
	if (TotalSize > Size) {
	    Overflow = TRUE;
	}

	/* Fill system information */
	if (!Overflow) {
	    /* Relative offset to the beginning of the next structure */
	    SpiCurrent->NextEntryOffset = CurrentSize + ImageNameMaximumLength;
	    SpiCurrent->NumberOfThreads = ThreadCount;
	    SpiCurrent->ImageName.Length = ImageNameLength;
	    SpiCurrent->ImageName.MaximumLength = ImageNameMaximumLength;
	    /* We make ImageName.Buffer a relative offset (from the start of this
	     * entry of SYSTEM_PROCESS_INFORMATION) since the client pointer is in
	     * a different address space. */
	    SpiCurrent->ImageName.Buffer = (PWSTR)CurrentSize;

	    /* Copy name to the end of the struct */
	    RtlUTF8ToUnicodeN((PWSTR)(Current + CurrentSize), ImageNameLength,
			      &ImageNameLength, ImageName, strlen(ImageName));

	    SpiCurrent->BasePriority = Process->BasePriority;
	    SpiCurrent->UniqueProcessId = (HANDLE)PsGetProcessId(Process);
	    SpiCurrent->InheritedFromUniqueProcessId = (HANDLE)
		Process->InheritedFromUniqueProcessId;

	    SpiCurrent->HandleCount = ObGetProcessHandleCount(Process);

	    SpiCurrent->PeakVirtualSize = Process->ImageVirtualSize;
	    SpiCurrent->VirtualSize = Process->ImageVirtualSize;
	    PSYSTEM_THREAD_INFORMATION ThreadInfo = (PVOID)(SpiCurrent + 1);

	    LoopOverList(Thread, &Process->ThreadList, THREAD, ThreadListEntry) {
		ThreadInfo->StartAddress = Thread->EntryPoint;
		ThreadInfo->ClientId = PsGetClientId(Thread);
		ThreadInfo->Priority = Thread->CurrentPriority;
		ThreadInfo->BasePriority = Thread->CurrentPriority;
		ThreadInfo->ThreadState = Thread->Suspended ? Standby : Running;
		ThreadInfo++;
	    }
	}

	Current += CurrentSize + ImageNameMaximumLength;
    }

    if (SpiCurrent && !Overflow) {
	SpiCurrent->NextEntryOffset = 0;
    }

    *ReqSize = TotalSize;
    return Overflow ? STATUS_BUFFER_TOO_SMALL : STATUS_SUCCESS;
}

static VOID EiGetDriverObjectCount(IN POBJECT Object,
				   IN PVOID Context)
{
    PULONG Count = Context;
    if (ObObjectGetType(Object) == OBJECT_TYPE_DRIVER) {
	++*Count;
    }
}

static VOID EiWriteDriverModuleInfo(IN POBJECT Object,
				    IN PVOID Context)
{
    PRTL_PROCESS_MODULE_INFORMATION *pInfo = Context;
    if (ObObjectGetType(Object) == OBJECT_TYPE_DRIVER) {
	PRTL_PROCESS_MODULE_INFORMATION Info = (*pInfo)++;
	PIO_DRIVER_OBJECT DriverObject = Object;
	Info->MappedBase = (PVOID)DriverObject->DriverProcess->InitInfo.ImageBase;
	Info->ImageBase =
	    (PVOID)DriverObject->DriverProcess->ImageSection->ImageSectionObject->ImageBase;
	Info->ImageSize = DriverObject->DriverProcess->ImageSection->Size;
	snprintf(Info->FullPathName, sizeof(Info->FullPathName),
		 "%s", DriverObject->DriverImagePath);
    }
}

/* Class 11 - Module Information */
QSI_DEF(SystemModuleInformation)
{
    *ReqSize = FIELD_OFFSET(RTL_PROCESS_MODULES, Modules);
    if (Size < *ReqSize) {
	return STATUS_BUFFER_TOO_SMALL;
    }
    PRTL_PROCESS_MODULES Modules = Buffer;
    /* Query the \Driver object directory for all drivers loaded in the system */
    POBJECT DriverObjectDirectory = NULL;
    RET_ERR(ObReferenceObjectByName(DRIVER_OBJECT_DIRECTORY,
				    OBJECT_TYPE_DIRECTORY,
				    FALSE, NULL,
				    &DriverObjectDirectory));
    ULONG DriverObjectCount = 0;
    ObDirectoryObjectVisitObject(DriverObjectDirectory, EiGetDriverObjectCount,
				 &DriverObjectCount);
    Modules->NumberOfModules = DriverObjectCount;
    *ReqSize = FIELD_OFFSET(RTL_PROCESS_MODULES, Modules) +
	DriverObjectCount * sizeof(RTL_PROCESS_MODULE_INFORMATION);
    if (Size < *ReqSize) {
	ObDereferenceObject(DriverObjectDirectory);
	return STATUS_BUFFER_TOO_SMALL;
    }
    PRTL_PROCESS_MODULE_INFORMATION Info = Modules->Modules;
    ObDirectoryObjectVisitObject(DriverObjectDirectory, EiWriteDriverModuleInfo,
				 &Info);
    ObDereferenceObject(DriverObjectDirectory);
    return STATUS_SUCCESS;
}

/* Query/Set Calls Table */
typedef struct _QSSI_CALLS {
    NTSTATUS(*Query) (PVOID, ULONG, PULONG);
    NTSTATUS(*Set) (PVOID, ULONG);
} QSSI_CALLS;

// QS    Query & Set
// QX    Query
// XS    Set
// XX    unknown behaviour
//
#define SI_QS(n) {QSI_USE(n),SSI_USE(n)}
#define SI_QX(n) {QSI_USE(n),NULL}
#define SI_XS(n) {NULL,SSI_USE(n)}
#define SI_XX(n) {NULL,NULL}

static QSSI_CALLS CallQS[] = {
    SI_QX(SystemBasicInformation),
    SI_QX(SystemProcessorInformation),
    SI_XX(SystemPerformanceInformation),    /* SI_QX(SystemPerformanceInformation) */
    SI_QX(SystemTimeOfDayInformation),
    SI_XX(SystemPathInformation),    /* SI_QX(SystemPathInformation) */
    SI_QX(SystemProcessInformation),
    SI_XX(SystemCallCountInformation),    /* SI_QX(SystemCallCountInformation) */
    SI_XX(SystemDeviceInformation),    /* SI_QX(SystemDeviceInformation) */
    SI_XX(SystemProcessorPerformanceInformation),    /* SI_QX(SystemProcessorPerformanceInformation) */
    SI_XX(SystemFlagsInformation),    /* SI_QS(SystemFlagsInformation) */
    SI_XX(SystemCallTimeInformation),    /* SI_QX(SystemCallTimeInformation) */	/* should be SI_XX */
    SI_QX(SystemModuleInformation),
    SI_XX(SystemLocksInformation),    /* SI_QX(SystemLocksInformation) */
    SI_XX(SystemStackTraceInformation),    /* SI_QX(SystemStackTraceInformation) */	/* should be SI_XX */
    SI_XX(SystemPagedPoolInformation),    /* SI_QX(SystemPagedPoolInformation) */	/* should be SI_XX */
    SI_XX(SystemNonPagedPoolInformation),    /* SI_QX(SystemNonPagedPoolInformation) */	/* should be SI_XX */
    SI_XX(SystemHandleInformation),    /* SI_QX(SystemHandleInformation) */
    SI_XX(SystemObjectInformation),    /* SI_QX(SystemObjectInformation) */
    SI_XX(SystemPageFileInformation),    /* SI_QX(SystemPageFileInformation) */
    SI_XX(SystemVdmInstemulInformation),    /* SI_QX(SystemVdmInstemulInformation) */
    SI_XX(SystemVdmBopInformation),    /* SI_QX(SystemVdmBopInformation) */	/* it should be SI_XX */
    SI_XX(SystemFileCacheInformation),    /* SI_QS(SystemFileCacheInformation) */
    SI_XX(SystemPoolTagInformation),    /* SI_QX(SystemPoolTagInformation) */
    SI_XX(SystemInterruptInformation),    /* SI_QX(SystemInterruptInformation) */
    SI_XX(SystemDpcBehaviourInformation),    /* SI_QS(SystemDpcBehaviourInformation) */
    SI_XX(SystemFullMemoryInformation),    /* SI_QX(SystemFullMemoryInformation) */	/* it should be SI_XX */
    SI_XX(SystemLoadGdiDriverInformation),    /* SI_XS(SystemLoadGdiDriverInformation) */
    SI_XX(SystemUnloadGdiDriverInformation),    /* SI_XS(SystemUnloadGdiDriverInformation) */
    SI_XX(SystemTimeAdjustmentInformation),    /* SI_QS(SystemTimeAdjustmentInformation) */
    SI_XX(SystemSummaryMemoryInformation),    /* SI_QX(SystemSummaryMemoryInformation) */	/* it should be SI_XX */
    SI_XX(SystemNextEventIdInformation),    /* SI_QX(SystemNextEventIdInformation) */	/* it should be SI_XX */
    SI_XX(SystemPerformanceTraceInformation),    /* SI_QX(SystemPerformanceTraceInformation) */	/* it should be SI_XX */
    SI_XX(SystemCrashDumpInformation),    /* SI_QX(SystemCrashDumpInformation) */
    SI_XX(SystemExceptionInformation),    /* SI_QX(SystemExceptionInformation) */
    SI_XX(SystemCrashDumpStateInformation),    /* SI_QX(SystemCrashDumpStateInformation) */
    SI_XX(SystemKernelDebuggerInformation),    /* SI_QX(SystemKernelDebuggerInformation) */
    SI_XX(SystemContextSwitchInformation),    /* SI_QX(SystemContextSwitchInformation) */
    SI_XX(SystemRegistryQuotaInformation),    /* SI_QS(SystemRegistryQuotaInformation) */
    SI_XX(SystemExtendServiceTableInformation),    /* SI_XS(SystemExtendServiceTableInformation) */
    SI_XX(SystemPrioritySeperation),    /* SI_XS(SystemPrioritySeperation) */
    SI_XX(SystemVerifierAddDriverInformation),    /* SI_QX(SystemVerifierAddDriverInformation) */	/* it should be SI_XX */
    SI_XX(SystemVerifierRemoveDriverInformation),    /* SI_QX(SystemVerifierRemoveDriverInformation) */	/* it should be SI_XX */
    SI_XX(SystemProcessorIdleInformation),    /* SI_QX(SystemProcessorIdleInformation) */	/* it should be SI_XX */
    SI_XX(SystemLegacyDriverInformation),    /* SI_QX(SystemLegacyDriverInformation) */	/* it should be SI_XX */
    SI_XX(SystemCurrentTimeZoneInformation),    /* SI_QS(SystemCurrentTimeZoneInformation) */	/* it should be SI_QX */
    SI_XX(SystemLookasideInformation),    /* SI_QX(SystemLookasideInformation) */
    SI_XX(SystemTimeSlipNotification),    /* SI_XS(SystemTimeSlipNotification) */
    SI_XX(SystemSessionCreate),    /* SI_XS(SystemSessionCreate) */
    SI_XX(SystemSessionDetach),    /* SI_XS(SystemSessionDetach) */
    SI_XX(SystemSessionInformation),    /* SI_QX(SystemSessionInformation) */	/* it should be SI_XX */
    SI_XX(SystemRangeStartInformation),    /* SI_QX(SystemRangeStartInformation) */
    SI_XX(SystemVerifierInformation),    /* SI_QS(SystemVerifierInformation) */
    SI_XX(SystemVerifierThunkExtend),    /* SI_XS(SystemVerifierThunkExtend) */
    SI_XX(SystemSessionProcessesInformation),    /* SI_QX(SystemSessionProcessesInformation) */
    SI_XX(SystemLoadGdiDriverInSystemSpaceInformation),    /* SI_XS(SystemLoadGdiDriverInSystemSpaceInformation) */
    SI_XX(SystemNumaProcessorMap),    /* SI_QX(SystemNumaProcessorMap) */
    SI_XX(SystemPrefetcherInformation),    /* SI_QX(SystemPrefetcherInformation) */
    SI_XX(SystemExtendedProcessInformation),    /* SI_QX(SystemExtendedProcessInformation) */
    SI_XX(SystemRecommendedSharedDataAlignment),    /* SI_QX(SystemRecommendedSharedDataAlignment) */
    SI_XX(SystemComPlusPackage),    /* SI_XX(SystemComPlusPackage) */
    SI_XX(SystemNumaAvailableMemory),    /* SI_QX(SystemNumaAvailableMemory) */
    SI_XX(SystemProcessorPowerInformation),	/* FIXME: not implemented */
    SI_XX(SystemEmulationBasicInformation),	/* FIXME: not implemented */
    SI_XX(SystemEmulationProcessorInformation),	/* FIXME: not implemented */
    SI_XX(SystemExtendedHandleInformation),    /* SI_QX(SystemExtendedHandleInformation) */
    SI_XX(SystemLostDelayedWriteInformation),	/* FIXME: not implemented */
    SI_XX(SystemBigPoolInformation),	/* FIXME: not implemented */
    SI_XX(SystemSessionPoolTagInformation),	/* FIXME: not implemented */
    SI_XX(SystemSessionMappedViewInformation),	/* FIXME: not implemented */
    SI_XX(SystemHotpatchInformation),	/* FIXME: not implemented */
    SI_XX(SystemObjectSecurityMode),    /* SI_QX(SystemObjectSecurityMode) */
    SI_XX(SystemWatchdogTimerHandler),	/* FIXME: not implemented */
    SI_XX(SystemWatchdogTimerInformation),	/* FIXME: not implemented */
    SI_XX(SystemLogicalProcessorInformation),    /* SI_QX(SystemLogicalProcessorInformation) */
    SI_XX(SystemWow64SharedInformation),	/* FIXME: not implemented */
    SI_XX(SystemRegisterFirmwareTableInformationHandler),	/* FIXME: not implemented */
    SI_XX(SystemFirmwareTableInformation),    /* SI_QX(SystemFirmwareTableInformation) */
};

C_ASSERT(SystemBasicInformation == 0);
#define MIN_SYSTEM_INFO_CLASS (SystemBasicInformation)
#define MAX_SYSTEM_INFO_CLASS RTL_NUMBER_OF(CallQS)

/*
 * @implemented
 */
NTSTATUS NtQuerySystemInformation(IN ASYNC_STATE State,
				  IN PTHREAD Thread,
                                  IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
                                  IN PVOID SystemInformationBuffer,
                                  IN ULONG SystemInformationLength,
                                  OUT OPTIONAL ULONG *ReturnLength)
{
    NTSTATUS Status = STATUS_NOT_IMPLEMENTED;

    /*
     * Check whether the request is valid.
     */
    if (SystemInformationClass < MIN_SYSTEM_INFO_CLASS ||
	SystemInformationClass >= MAX_SYSTEM_INFO_CLASS) {
	return STATUS_INVALID_INFO_CLASS;
    }

    if (CallQS[SystemInformationClass].Query != NULL) {
	/* Hand the request to a subhandler */
	ULONG CapturedResultLength = 0;
	Status = CallQS[SystemInformationClass].Query(SystemInformationBuffer,
						      SystemInformationLength,
						      &CapturedResultLength);

	/* Save the result length to the caller */
	if (ReturnLength)
	    *ReturnLength = CapturedResultLength;
    }

    return Status;
}
