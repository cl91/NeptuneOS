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
    PSYSTEM_PROCESSOR_INFORMATION Spi = (PSYSTEM_PROCESSOR_INFORMATION) Buffer;

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
    KeQuerySystemTime(&CurrentTime);

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

/* Query/Set Calls Table */
typedef
    struct _QSSI_CALLS {
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

static
 QSSI_CALLS CallQS[] = {
    SI_QX(SystemBasicInformation),
    SI_QX(SystemProcessorInformation),
    NULL,    /* SI_QX(SystemPerformanceInformation) */
    SI_QX(SystemTimeOfDayInformation),
    NULL,    /* SI_QX(SystemPathInformation) */
    NULL,    /* SI_QX(SystemProcessInformation) */
    NULL,    /* SI_QX(SystemCallCountInformation) */
    NULL,    /* SI_QX(SystemDeviceInformation) */
    NULL,    /* SI_QX(SystemProcessorPerformanceInformation) */
    NULL,    /* SI_QS(SystemFlagsInformation) */
    NULL,    /* SI_QX(SystemCallTimeInformation) */	/* should be SI_XX */
    NULL,    /* SI_QX(SystemModuleInformation) */
    NULL,    /* SI_QX(SystemLocksInformation) */
    NULL,    /* SI_QX(SystemStackTraceInformation) */	/* should be SI_XX */
    NULL,    /* SI_QX(SystemPagedPoolInformation) */	/* should be SI_XX */
    NULL,    /* SI_QX(SystemNonPagedPoolInformation) */	/* should be SI_XX */
    NULL,    /* SI_QX(SystemHandleInformation) */
    NULL,    /* SI_QX(SystemObjectInformation) */
    NULL,    /* SI_QX(SystemPageFileInformation) */
    NULL,    /* SI_QX(SystemVdmInstemulInformation) */
    NULL,    /* SI_QX(SystemVdmBopInformation) */	/* it should be SI_XX */
    NULL,    /* SI_QS(SystemFileCacheInformation) */
    NULL,    /* SI_QX(SystemPoolTagInformation) */
    NULL,    /* SI_QX(SystemInterruptInformation) */
    NULL,    /* SI_QS(SystemDpcBehaviourInformation) */
    NULL,    /* SI_QX(SystemFullMemoryInformation) */	/* it should be SI_XX */
    NULL,    /* SI_XS(SystemLoadGdiDriverInformation) */
    NULL,    /* SI_XS(SystemUnloadGdiDriverInformation) */
    NULL,    /* SI_QS(SystemTimeAdjustmentInformation) */
    NULL,    /* SI_QX(SystemSummaryMemoryInformation) */	/* it should be SI_XX */
    NULL,    /* SI_QX(SystemNextEventIdInformation) */	/* it should be SI_XX */
    NULL,    /* SI_QX(SystemPerformanceTraceInformation) */	/* it should be SI_XX */
    NULL,    /* SI_QX(SystemCrashDumpInformation) */
    NULL,    /* SI_QX(SystemExceptionInformation) */
    NULL,    /* SI_QX(SystemCrashDumpStateInformation) */
    NULL,    /* SI_QX(SystemKernelDebuggerInformation) */
    NULL,    /* SI_QX(SystemContextSwitchInformation) */
    NULL,    /* SI_QS(SystemRegistryQuotaInformation) */
    NULL,    /* SI_XS(SystemExtendServiceTableInformation) */
    NULL,    /* SI_XS(SystemPrioritySeperation) */
    NULL,    /* SI_QX(SystemVerifierAddDriverInformation) */	/* it should be SI_XX */
    NULL,    /* SI_QX(SystemVerifierRemoveDriverInformation) */	/* it should be SI_XX */
    NULL,    /* SI_QX(SystemProcessorIdleInformation) */	/* it should be SI_XX */
    NULL,    /* SI_QX(SystemLegacyDriverInformation) */	/* it should be SI_XX */
    NULL,    /* SI_QS(SystemCurrentTimeZoneInformation) */	/* it should be SI_QX */
    NULL,    /* SI_QX(SystemLookasideInformation) */
    NULL,    /* SI_XS(SystemTimeSlipNotification) */
    NULL,    /* SI_XS(SystemSessionCreate) */
    NULL,    /* SI_XS(SystemSessionDetach) */
    NULL,    /* SI_QX(SystemSessionInformation) */	/* it should be SI_XX */
    NULL,    /* SI_QX(SystemRangeStartInformation) */
    NULL,    /* SI_QS(SystemVerifierInformation) */
    NULL,    /* SI_XS(SystemVerifierThunkExtend) */
    NULL,    /* SI_QX(SystemSessionProcessesInformation) */
    NULL,    /* SI_XS(SystemLoadGdiDriverInSystemSpaceInformation) */
    NULL,    /* SI_QX(SystemNumaProcessorMap) */
    NULL,    /* SI_QX(SystemPrefetcherInformation) */
    NULL,    /* SI_QX(SystemExtendedProcessInformation) */
    NULL,    /* SI_QX(SystemRecommendedSharedDataAlignment) */
    NULL,    /* SI_XX(SystemComPlusPackage) */
    NULL,    /* SI_QX(SystemNumaAvailableMemory) */
    NULL,    /* SI_XX(SystemProcessorPowerInformation) */	/* FIXME: not implemented */
    NULL,    /* SI_XX(SystemEmulationBasicInformation) */	/* FIXME: not implemented */
    NULL,    /* SI_XX(SystemEmulationProcessorInformation) */	/* FIXME: not implemented */
    NULL,    /* SI_QX(SystemExtendedHandleInformation) */
    NULL,    /* SI_XX(SystemLostDelayedWriteInformation) */	/* FIXME: not implemented */
    NULL,    /* SI_XX(SystemBigPoolInformation) */	/* FIXME: not implemented */
    NULL,    /* SI_XX(SystemSessionPoolTagInformation) */	/* FIXME: not implemented */
    NULL,    /* SI_XX(SystemSessionMappedViewInformation) */	/* FIXME: not implemented */
    NULL,    /* SI_XX(SystemHotpatchInformation) */	/* FIXME: not implemented */
    NULL,    /* SI_QX(SystemObjectSecurityMode) */
    NULL,    /* SI_XX(SystemWatchdogTimerHandler) */	/* FIXME: not implemented */
    NULL,    /* SI_XX(SystemWatchdogTimerInformation) */	/* FIXME: not implemented */
    NULL,    /* SI_QX(SystemLogicalProcessorInformation) */
    NULL,    /* SI_XX(SystemWow64SharedInformation) */	/* FIXME: not implemented */
    NULL,    /* SI_XX(SystemRegisterFirmwareTableInformationHandler) */	/* FIXME: not implemented */
    NULL,    /* SI_QX(SystemFirmwareTableInformation) */
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

    PVOID MappedUserBuffer = NULL;
    RET_ERR(MmMapUserBuffer(&Thread->Process->VSpace,
			    (MWORD)SystemInformationBuffer,
			    SystemInformationLength,
			    &MappedUserBuffer));
    assert(MappedUserBuffer != NULL);

    if (CallQS[SystemInformationClass].Query != NULL) {
	/* Hand the request to a subhandler */
	ULONG CapturedResultLength = 0;
	Status = CallQS[SystemInformationClass].Query(MappedUserBuffer,
						      SystemInformationLength,
						      &CapturedResultLength);

	/* Save the result length to the caller */
	if (ReturnLength)
	    *ReturnLength = CapturedResultLength;
    }

    if (MappedUserBuffer != NULL) {
	MmUnmapUserBuffer(MappedUserBuffer);
    }

    return Status;
}
