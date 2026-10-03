#pragma once

#include <ntbasedef.h>
#include <exbasedef.h>

/*
 * Firmware variable attributes
 */
#define VARIABLE_ATTRIBUTE_NON_VOLATILE                             0x00000001
#define VARIABLE_ATTRIBUTE_BOOTSERVICE_ACCESS                       0x00000002
#define VARIABLE_ATTRIBUTE_RUNTIME_ACCESS                           0x00000004
#define VARIABLE_ATTRIBUTE_HARDWARE_ERROR_RECORD                    0x00000008
#define VARIABLE_ATTRIBUTE_AUTHENTICATED_WRITE_ACCESS               0x00000010
#define VARIABLE_ATTRIBUTE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS    0x00000020
#define VARIABLE_ATTRIBUTE_APPEND_WRITE                             0x00000040

typedef USHORT RTL_ATOM, *PRTL_ATOM;

/*
 * Event Types
 */
typedef enum _EVENT_TYPE {
    NotificationEvent,
    SynchronizationEvent
} EVENT_TYPE;

/*
 * Timer Types
 */
typedef enum _TIMER_TYPE {
    NotificationTimer,
    SynchronizationTimer
} TIMER_TYPE;

/*
 * Timer APC Routine
 */
typedef VOID (NTAPI *PTIMER_APC_ROUTINE)(IN PVOID TimerContext,
					 IN ULONG TimerLowValue,
					 IN LONG TimerHighValue);

/*
 * Shutdown types for NtShutdownSystem
 */
typedef enum _SHUTDOWN_ACTION {
    ShutdownNoReboot,
    ShutdownReboot,
    ShutdownPowerOff
} SHUTDOWN_ACTION;

/*
 * Parameters for NtRaiseHardError
 */
#define MAXIMUM_HARDERROR_PARAMETERS        5
#define HARDERROR_OVERRIDE_ERRORMODE        0x10000000

/*
 * Responses for NtRaiseHardError
 */
typedef enum _HARDERROR_RESPONSE_OPTION {
    OptionAbortRetryIgnore,
    OptionOk,
    OptionOkCancel,
    OptionRetryCancel,
    OptionYesNo,
    OptionYesNoCancel,
    OptionShutdownSystem,
    OptionOkNoWait,
    OptionCancelTryContinue
} HARDERROR_RESPONSE_OPTION, *PHARDERROR_RESPONSE_OPTION;

typedef enum _HARDERROR_RESPONSE {
    ResponseReturnToCaller,
    ResponseNotHandled,
    ResponseAbort,
    ResponseCancel,
    ResponseIgnore,
    ResponseNo,
    ResponseOk,
    ResponseRetry,
    ResponseYes,
    ResponseTryAgain,
    ResponseContinue
} HARDERROR_RESPONSE, *PHARDERROR_RESPONSE;

/*
 * System Information Classes for NtQueryEvent
 */
typedef enum _EVENT_INFORMATION_CLASS {
    EventBasicInformation
} EVENT_INFORMATION_CLASS;

/*
 * Information Structures for NtQueryEvent
 */
typedef struct _EVENT_BASIC_INFORMATION {
    EVENT_TYPE EventType;
    LONG EventState;
} EVENT_BASIC_INFORMATION, *PEVENT_BASIC_INFORMATION;

/*
 * System Information Classes for NtQueryAtom
 */
typedef enum _ATOM_INFORMATION_CLASS {
    AtomBasicInformation,
    AtomTableInformation,
} ATOM_INFORMATION_CLASS;

/*
 * Information Structures for NtQueryAtom
 */
typedef struct _ATOM_BASIC_INFORMATION {
    USHORT UsageCount;
    USHORT Flags;
    USHORT NameLength;
    WCHAR Name[1];
} ATOM_BASIC_INFORMATION, *PATOM_BASIC_INFORMATION;

typedef struct _ATOM_TABLE_INFORMATION {
    ULONG NumberOfAtoms;
    USHORT Atoms[1];
} ATOM_TABLE_INFORMATION, *PATOM_TABLE_INFORMATION;

/*
 *  System Information Classes for NtQuerySystemInformation
 */
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation                                = 0, // 0x0
    SystemProcessorInformation                            = 1, // 0x1
    SystemPerformanceInformation                          = 2, // 0x2
    SystemTimeOfDayInformation                            = 3, // 0x3
    SystemPathInformation                                 = 4, // 0x4 - Obsolete:
                                                               //       Use KUSER_SHARED_DATA
    SystemProcessInformation                              = 5, // 0x5
    SystemCallCountInformation                            = 6, // 0x6
    SystemDeviceInformation                               = 7, // 0x7
    SystemProcessorPerformanceInformation                 = 8, // 0x8
    SystemFlagsInformation                                = 9, // 0x9
    SystemCallTimeInformation                             = 10, // 0xA
    SystemModuleInformation                               = 11, // 0xB
    SystemLocksInformation                                = 12, // 0xC
    SystemStackTraceInformation                           = 13, // 0xD
    SystemPagedPoolInformation                            = 14, // 0xE
    SystemNonPagedPoolInformation                         = 15, // 0xF
    SystemHandleInformation                               = 16, // 0x10
    SystemObjectInformation                               = 17, // 0x11
    SystemPageFileInformation                             = 18, // 0x12
    SystemVdmInstemulInformation                          = 19, // 0x13
    SystemVdmBopInformation                               = 20, // 0x14
    SystemFileCacheInformation                            = 21, // 0x15
    SystemPoolTagInformation                              = 22, // 0x16
    SystemInterruptInformation                            = 23, // 0x17
    SystemDpcBehaviorInformation                          = 24, // 0x18
    SystemFullMemoryInformation                           = 25, // 0x19
    SystemLoadGdiDriverInformation                        = 26, // 0x1A
    SystemUnloadGdiDriverInformation                      = 27, // 0x1B
    SystemTimeAdjustmentInformation                       = 28, // 0x1C
    SystemSummaryMemoryInformation                        = 29, // 0x1D
    SystemMirrorMemoryInformation                         = 30, // 0x1E
    SystemPerformanceTraceInformation                     = 31, // 0x1F
    SystemBootConsoleInformation                          = 32, // 0x20
    SystemExceptionInformation                            = 33, // 0x21
    SystemCrashDumpStateInformation                       = 34, // 0x22
    SystemKernelDebuggerInformation                       = 35, // 0x23
    SystemContextSwitchInformation                        = 36, // 0x24
    SystemRegistryQuotaInformation                        = 37, // 0x25
    SystemExtendServiceTableInformation                   = 38, // 0x26
    SystemPrioritySeperation                              = 39, // 0x27
    SystemVerifierAddDriverInformation                    = 40, // 0x28
    SystemVerifierRemoveDriverInformation                 = 41, // 0x29
    SystemProcessorIdleInformation                        = 42, // 0x2A
    SystemLegacyDriverInformation                         = 43, // 0x2B
    SystemCurrentTimeZoneInformation                      = 44, // 0x2C
    SystemLookasideInformation                            = 45, // 0x2D
    SystemTimeSlipNotification                            = 46, // 0x2E
    SystemSessionCreate                                   = 47, // 0x2F
    SystemSessionDetach                                   = 48, // 0x30
    SystemSessionInformation                              = 49, // 0x31
    SystemRangeStartInformation                           = 50, // 0x32
    SystemVerifierInformation                             = 51, // 0x33
    SystemVerifierThunkExtend                             = 52, // 0x34 - Win 11: SystemVerifierReserved
    SystemSessionProcessInformation                       = 53, // 0x35
    SystemLoadGdiDriverInSystemSpace                      = 54, // 0x36
    SystemNumaProcessorMap                                = 55, // 0x37
    SystemPrefetcherInformation                           = 56, // 0x38
    SystemExtendedProcessInformation                      = 57, // 0x39
    SystemRecommendedSharedDataAlignment                  = 58, // 0x3A
    SystemComPlusPackage                                  = 59, // 0x3B
    SystemNumaAvailableMemory                             = 60, // 0x3C
    SystemProcessorPowerInformation                       = 61, // 0x3D
    SystemEmulationBasicInformation                       = 62, // 0x3E
    SystemEmulationProcessorInformation                   = 63, // 0x3F
    SystemExtendedHandleInformation                       = 64, // 0x40
    SystemLostDelayedWriteInformation                     = 65, // 0x41
    SystemBigPoolInformation                              = 66, // 0x42
    SystemSessionPoolTagInformation                       = 67, // 0x43
    SystemSessionMappedViewInformation                    = 68, // 0x44
    SystemHotpatchInformation                             = 69, // 0x45
    SystemObjectSecurityMode                              = 70, // 0x46
    SystemWatchdogTimerHandler                            = 71, // 0x47
    SystemWatchdogTimerInformation                        = 72, // 0x48
    SystemLogicalProcessorInformation                     = 73, // 0x49
    SystemWow64SharedInformationObsolete                  = 74, // 0x4A
    SystemRegisterFirmwareTableInformationHandler         = 75, // 0x4B
    SystemFirmwareTableInformation                        = 76, // 0x4C
    SystemModuleInformationEx                             = 77, // 0x4D
    SystemVerifierTriageInformation                       = 78, // 0x4E
    SystemSuperfetchInformation                           = 79, // 0x4F
    SystemMemoryListInformation                           = 80, // 0x50
    SystemFileCacheInformationEx                          = 81, // 0x51
    SystemThreadPriorityClientIdInformation               = 82, // 0x52
    SystemProcessorIdleCycleTimeInformation               = 83, // 0x53
    SystemVerifierCancellationInformation                 = 84, // 0x54
    SystemProcessorPowerInformationEx                     = 85, // 0x55
    SystemRefTraceInformation                             = 86, // 0x56
    SystemSpecialPoolInformation                          = 87, // 0x57
    SystemProcessIdInformation                            = 88, // 0x58
    SystemErrorPortInformation                            = 89, // 0x59
    SystemBootEnvironmentInformation                      = 90, // 0x5A
    SystemHypervisorInformation                           = 91, // 0x5B
    SystemVerifierInformationEx                           = 92, // 0x5C
    SystemTimeZoneInformation                             = 93, // 0x5D
    SystemImageFileExecutionOptionsInformation            = 94, // 0x5E
    SystemCoverageInformation                             = 95, // 0x5F
    SystemPrefetchPatchInformation                        = 96, // 0x60
    SystemVerifierFaultsInformation                       = 97, // 0x61
    SystemSystemPartitionInformation                      = 98, // 0x62
    SystemSystemDiskInformation                           = 99, // 0x63
    SystemProcessorPerformanceDistribution                = 100, // 0x64
    SystemNumaProximityNodeInformation                    = 101, // 0x65
    SystemDynamicTimeZoneInformation                      = 102, // 0x66
    SystemCodeIntegrityInformation                        = 103, // 0x67
    SystemProcessorMicrocodeUpdateInformation             = 104, // 0x68
    SystemProcessorBrandString                            = 105, // 0x69
    SystemVirtualAddressInformation                       = 106, // 0x6A
    SystemLogicalProcessorAndGroupInformation             = 107, // 0x6B
    SystemProcessorCycleTimeInformation                   = 108, // 0x6C
    SystemStoreInformation                                = 109, // 0x6D
    SystemRegistryAppendString                            = 110, // 0x6E
    SystemAitSamplingValue                                = 111, // 0x6F
    SystemVhdBootInformation                              = 112, // 0x70
    SystemCpuQuotaInformation                             = 113, // 0x71
    SystemNativeBasicInformation                          = 114, // 0x72
    SystemErrorPortTimeouts                               = 115, // 0x73
    SystemLowPriorityIoInformation                        = 116, // 0x74
    SystemBootEntropyInformation                          = 117, // 0x75
    SystemVerifierCountersInformation                     = 118, // 0x76
    SystemPagedPoolInformationEx                          = 119, // 0x77
    SystemSystemPtesInformationEx                         = 120, // 0x78
    SystemNodeDistanceInformation                         = 121, // 0x79
    SystemAcpiAuditInformation                            = 122, // 0x7A
    SystemBasicPerformanceInformation                     = 123, // 0x7B
    SystemQueryPerformanceCounterInformation              = 124, // 0x7C
    SystemSessionBigPoolInformation                       = 125, // 0x7D
    SystemBootGraphicsInformation                         = 126, // 0x7E
    SystemScrubPhysicalMemoryInformation                  = 127, // 0x7F
    SystemBadPageInformation                              = 128, // 0x80
    SystemProcessorProfileControlArea                     = 129, // 0x81
    SystemCombinePhysicalMemoryInformation                = 130, // 0x82
    SystemEntropyInterruptTimingInformation               = 131, // 0x83
    SystemConsoleInformation                              = 132, // 0x84
    SystemPlatformBinaryInformation                       = 133, // 0x85
    SystemThrottleNotificationInformation                 = 134, // 0x86 - 6.2 only
    SystemPolicyInformation                               = 134, // 0x86 - 6.3 and higher
    SystemHypervisorProcessorCountInformation             = 135, // 0x87
    SystemDeviceDataInformation                           = 136, // 0x88
    SystemDeviceDataEnumerationInformation                = 137, // 0x89
    SystemMemoryTopologyInformation                       = 138, // 0x8A
    SystemMemoryChannelInformation                        = 139, // 0x8B
    SystemBootLogoInformation                             = 140, // 0x8C
    SystemProcessorPerformanceInformationEx               = 141, // 0x8D
    SystemSpare0                                          = 142, // 0x8E - 6.2 to 1511
    SystemCriticalProcessErrorLogInformation              = 142, // 0x8E - 1607 and higher
    SystemSecureBootPolicyInformation                     = 143, // 0x8F
    SystemPageFileInformationEx                           = 144, // 0x90
    SystemSecureBootInformation                           = 145, // 0x91
    SystemEntropyInterruptTimingRawInformation            = 146, // 0x92
    SystemPortableWorkspaceEfiLauncherInformation         = 147, // 0x93
    SystemFullProcessInformation                          = 148, // 0x94
    SystemKernelDebuggerInformationEx                     = 149, // 0x95
    SystemBootMetadataInformation                         = 150, // 0x96
    SystemSoftRebootInformation                           = 151, // 0x97
    SystemElamCertificateInformation                      = 152, // 0x98
    SystemOfflineDumpConfigInformation                    = 153, // 0x99
    SystemProcessorFeaturesInformation                    = 154, // 0x9A
    SystemRegistryReconciliationInformation               = 155, // 0x9B
    SystemEdidInformation                                 = 156, // 0x9C
    SystemManufacturingInformation                        = 157, // 0x9D
    SystemEnergyEstimationConfigInformation               = 158, // 0x9E
    SystemHypervisorDetailInformation                     = 159, // 0x9F
    SystemProcessorCycleStatsInformation                  = 160, // 0xA0
    SystemVmGenerationCountInformation                    = 161, // 0xA1
    SystemTrustedPlatformModuleInformation                = 162, // 0xA2
    SystemKernelDebuggerFlags                             = 163, // 0xA3
    SystemCodeIntegrityPolicyInformation                  = 164, // 0xA4
    SystemIsolatedUserModeInformation                     = 165, // 0xA5
    SystemHardwareSecurityTestInterfaceResultsInformation = 166, // 0xA6
    SystemSingleModuleInformation                         = 167, // 0xA7
    SystemAllowedCpuSetsInformation                       = 168, // 0xA8
    SystemVsmProtectionInformation                        = 169, // 0xA9 - aka SystemDmaProtectionInformation
    SystemInterruptCpuSetsInformation                     = 170, // 0xAA
    SystemSecureBootPolicyFullInformation                 = 171, // 0xAB
    SystemCodeIntegrityPolicyFullInformation              = 172, // 0xAC
    SystemAffinitizedInterruptProcessorInformation        = 173, // 0xAD
    SystemRootSiloInformation                             = 174, // 0xAE
    SystemCpuSetInformation                               = 175, // 0xAF
    SystemCpuSetTagInformation                            = 176, // 0xB0
    SystemWin32WerStartCallout                            = 177, // 0xB1
    SystemSecureKernelProfileInformation                  = 178, // 0xB2
    SystemCodeIntegrityPlatformManifestInformation        = 179, // 0xB3
    SystemInterruptSteeringInformation                    = 180, // 0xB4
    SystemSupportedProcessorArchitectures                 = 181, // 0xB5
    SystemMemoryUsageInformation                          = 182, // 0xB6
    SystemCodeIntegrityCertificateInformation             = 183, // 0xB7
    SystemPhysicalMemoryInformation                       = 184, // 0xB8
    SystemControlFlowTransition                           = 185, // 0xB9
    SystemKernelDebuggingAllowed                          = 186, // 0xBA
    SystemActivityModerationExeState                      = 187, // 0xBB
    SystemActivityModerationUserSettings                  = 188, // 0xBC
    SystemCodeIntegrityPoliciesFullInformation            = 189, // 0xBD
    SystemCodeIntegrityUnlockInformation                  = 190, // 0xBE
    SystemIntegrityQuotaInformation                       = 191, // 0xBF
    SystemFlushInformation                                = 192, // 0xC0
    SystemProcessorIdleMaskInformation                    = 193, // 0xC1
    SystemSecureDumpEncryptionInformation                 = 194, // 0xC2
    SystemWriteConstraintInformation                      = 195, // 0xC3
    SystemKernelVaShadowInformation                       = 196, // 0xC4
    SystemHypervisorSharedPageInformation                 = 197, // 0xC5
    SystemFirmwareBootPerformanceInformation              = 198, // 0xC6
    SystemCodeIntegrityVerificationInformation            = 199, // 0xC7
    SystemFirmwarePartitionInformation                    = 200, // 0xC8
    SystemSpeculationControlInformation                   = 201, // 0xC9
    SystemDmaGuardPolicyInformation                       = 202, // 0xCA
    SystemEnclaveLaunchControlInformation                 = 203, // 0xCB
    SystemWorkloadAllowedCpuSetsInformation               = 204, // 0xCC
    SystemCodeIntegrityUnlockModeInformation              = 205, // 0xCD
    SystemLeapSecondInformation                           = 206, // 0xCE
    SystemFlags2Information                               = 207, // 0xCF
    SystemSecurityModelInformation                        = 208, // 0xD0
    SystemCodeIntegritySyntheticCacheInformation          = 209, // 0xD1
    SystemFeatureConfigurationInformation                 = 210, // 0xD2
    SystemFeatureConfigurationSectionInformation          = 211, // 0xD3
    SystemFeatureUsageSubscriptionInformation             = 212, // 0xD4
    SystemSecureSpeculationControlInformation             = 213, // 0xD5
    SystemSpacesBootInformation                           = 214, // 0xD6
    SystemFwRamdiskInformation                            = 215, // 0xD7
    SystemWheaIpmiHardwareInformation                     = 216, // 0xD8
    SystemDifSetRuleClassInformation                      = 217, // 0xD9
    SystemDifClearRuleClassInformation                    = 218, // 0xDA
    SystemDifApplyPluginVerificationOnDriver              = 219, // 0xDB
    SystemDifRemovePluginVerificationOnDriver             = 220, // 0xDC
    SystemShadowStackInformation                          = 221, // 0xDD
    SystemBuildVersionInformation                         = 222, // 0xDE
    SystemPoolLimitInformation                            = 223, // 0xDF
    SystemCodeIntegrityAddDynamicStore                    = 224, // 0xE0
    SystemCodeIntegrityClearDynamicStores                 = 225, // 0xE1
    SystemDifPoolTrackingInformation                      = 226, // 0xE2 - Win 11
    SystemPoolZeroingInformation                          = 227, // 0xE3
    SystemDpcWatchdogInformation                          = 228, // 0xE4
    SystemDpcWatchdogInformation2                         = 229, // 0xE5
    SystemSupportedProcessorArchitectures2                = 230, // 0xE6
    SystemSingleProcessorRelationshipInformation          = 231, // 0xE7
    SystemXfgCheckFailureInformation                      = 232, // 0xE8
    SystemIommuStateInformation                           = 233, // 0xE9
    SystemHypervisorMinrootInformation                    = 234, // 0xEA
    SystemHypervisorBootPagesInformation                  = 235, // 0xEB
    SystemPointerAuthInformation                          = 236, // 0xEC
    SystemSecureKernelDebuggerInformation                 = 237, // 0xED
    SystemOriginalImageFeatureInformation                 = 238, // 0xEE
    SystemMemoryNumaInformation                           = 239, // 0xEF
    SystemMemoryNumaPerformanceInformation                = 240, // 0xF0
    SystemCodeIntegritySignedPoliciesFullInformation      = 241, // 0xF1
    SystemSecureSecretsInformation                        = 242, // 0xF2
    SystemTrustedAppsRuntimeInformation                   = 243, // 0xF3
    SystemBadPageInformationEx                            = 244, // 0xF4
    SystemResourceDeadlockTimeout                         = 245, // 0xF5
    SystemBreakOnContextUnwindFailureInformation          = 246, // 0xF6
    SystemOslRamdiskInformation                           = 247, // 0xF7

    MaxSystemInfoClass
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

/*
 * Information Structures for NtQuerySystemInformation
 */
typedef struct _SYSTEM_BASIC_INFORMATION {
    ULONG Reserved;
    ULONG TimerResolution;
    ULONG PageSize;
    ULONG NumberOfPhysicalPages;
    ULONG LowestPhysicalPageNumber;
    ULONG HighestPhysicalPageNumber;
    ULONG AllocationGranularity;
    ULONG_PTR MinimumUserModeAddress;
    ULONG_PTR MaximumUserModeAddress;
    ULONG_PTR ActiveProcessorsAffinityMask;
    CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;

// Class 1
typedef struct _SYSTEM_PROCESSOR_INFORMATION {
    USHORT ProcessorArchitecture;
    USHORT ProcessorLevel;
    USHORT ProcessorRevision;
    USHORT MaximumProcessors;
    ULONG ProcessorFeatureBits;
} SYSTEM_PROCESSOR_INFORMATION, *PSYSTEM_PROCESSOR_INFORMATION;

// Class 2
typedef struct _SYSTEM_PERFORMANCE_INFORMATION {
    LARGE_INTEGER IdleProcessTime;
    LARGE_INTEGER IoReadTransferCount;
    LARGE_INTEGER IoWriteTransferCount;
    LARGE_INTEGER IoOtherTransferCount;
    ULONG IoReadOperationCount;
    ULONG IoWriteOperationCount;
    ULONG IoOtherOperationCount;
    ULONG AvailablePages;
    ULONG CommittedPages;
    ULONG CommitLimit;
    ULONG PeakCommitment;
    ULONG PageFaultCount;
    ULONG CopyOnWriteCount;
    ULONG TransitionCount;
    ULONG CacheTransitionCount;
    ULONG DemandZeroCount;
    ULONG PageReadCount;
    ULONG PageReadIoCount;
    ULONG CacheReadCount;
    ULONG CacheIoCount;
    ULONG DirtyPagesWriteCount;
    ULONG DirtyWriteIoCount;
    ULONG MappedPagesWriteCount;
    ULONG MappedWriteIoCount;
    ULONG PagedPoolPages;
    ULONG NonPagedPoolPages;
    ULONG PagedPoolAllocs;
    ULONG PagedPoolFrees;
    ULONG NonPagedPoolAllocs;
    ULONG NonPagedPoolFrees;
    ULONG FreeSystemPtes;
    ULONG ResidentSystemCodePage;
    ULONG TotalSystemDriverPages;
    ULONG TotalSystemCodePages;
    ULONG NonPagedPoolLookasideHits;
    ULONG PagedPoolLookasideHits;
    ULONG Spare3Count;
    ULONG ResidentSystemCachePage;
    ULONG ResidentPagedPoolPage;
    ULONG ResidentSystemDriverPage;
    ULONG CcFastReadNoWait;
    ULONG CcFastReadWait;
    ULONG CcFastReadResourceMiss;
    ULONG CcFastReadNotPossible;
    ULONG CcFastMdlReadNoWait;
    ULONG CcFastMdlReadWait;
    ULONG CcFastMdlReadResourceMiss;
    ULONG CcFastMdlReadNotPossible;
    ULONG CcMapDataNoWait;
    ULONG CcMapDataWait;
    ULONG CcMapDataNoWaitMiss;
    ULONG CcMapDataWaitMiss;
    ULONG CcPinMappedDataCount;
    ULONG CcPinReadNoWait;
    ULONG CcPinReadWait;
    ULONG CcPinReadNoWaitMiss;
    ULONG CcPinReadWaitMiss;
    ULONG CcCopyReadNoWait;
    ULONG CcCopyReadWait;
    ULONG CcCopyReadNoWaitMiss;
    ULONG CcCopyReadWaitMiss;
    ULONG CcMdlReadNoWait;
    ULONG CcMdlReadWait;
    ULONG CcMdlReadNoWaitMiss;
    ULONG CcMdlReadWaitMiss;
    ULONG CcReadAheadIos;
    ULONG CcLazyWriteIos;
    ULONG CcLazyWritePages;
    ULONG CcDataFlushes;
    ULONG CcDataPages;
    ULONG ContextSwitches;
    ULONG FirstLevelTbFills;
    ULONG SecondLevelTbFills;
    ULONG SystemCalls;
} SYSTEM_PERFORMANCE_INFORMATION, *PSYSTEM_PERFORMANCE_INFORMATION;

// Class 3
typedef struct _SYSTEM_TIMEOFDAY_INFORMATION {
    LARGE_INTEGER BootTime;
    LARGE_INTEGER CurrentTime;
    LARGE_INTEGER TimeZoneBias;
    ULONG TimeZoneId;
    ULONG Reserved;
    ULONGLONG BootTimeBias;
    ULONGLONG SleepTimeBias;
} SYSTEM_TIMEOFDAY_INFORMATION, *PSYSTEM_TIMEOFDAY_INFORMATION;

// Class 4
// This class is obsolete, please use KUSER_SHARED_DATA instead

//
// Thread States (SYSTEM_THREAD_INFORMATION::ThreadState).
//
typedef enum _KTHREAD_STATE {
    Initialized,
    Ready,
    Running,
    Standby,
    Terminated,
    Waiting,
    Transition,
    DeferredReady
} KTHREAD_STATE, *PKTHREAD_STATE;

// Class 5
typedef struct _SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
    ULONG PadPadAlignment;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

#ifndef _WIN64
C_ASSERT(sizeof(SYSTEM_THREAD_INFORMATION) == 0x40); // Must be 8-byte aligned
#endif

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize; //VISTA
    ULONG HardFaultCount; //WIN7
    ULONG NumberOfThreadsHighWatermark; //WIN7
    ULONGLONG CycleTime; //WIN7
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR PageDirectoryBase;

    //
    // This part corresponds to VM_COUNTERS_EX.
    // NOTE: *NOT* THE SAME AS VM_COUNTERS!
    //
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;

    //
    // This part corresponds to IO_COUNTERS
    //
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
//    SYSTEM_THREAD_INFORMATION TH[1];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

#ifndef _WIN64
C_ASSERT(sizeof(SYSTEM_PROCESS_INFORMATION) == 0xB8); // Must be 8-byte aligned
#endif

//
// Class 6
typedef struct _SYSTEM_CALL_COUNT_INFORMATION {
    ULONG Length;
    ULONG NumberOfTables;
} SYSTEM_CALL_COUNT_INFORMATION, *PSYSTEM_CALL_COUNT_INFORMATION;

// Class 7
typedef struct _SYSTEM_DEVICE_INFORMATION {
    ULONG NumberOfDisks;
    ULONG NumberOfFloppies;
    ULONG NumberOfCdRoms;
    ULONG NumberOfTapes;
    ULONG NumberOfSerialPorts;
    ULONG NumberOfParallelPorts;
} SYSTEM_DEVICE_INFORMATION, *PSYSTEM_DEVICE_INFORMATION;

// Class 8
typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION {
    LARGE_INTEGER IdleTime;
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER DpcTime;
    LARGE_INTEGER InterruptTime;
    ULONG InterruptCount;
} SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION, *PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;

// Class 9
typedef struct _SYSTEM_FLAGS_INFORMATION {
    ULONG Flags;
} SYSTEM_FLAGS_INFORMATION, *PSYSTEM_FLAGS_INFORMATION;

// Class 10
typedef struct _SYSTEM_CALL_TIME_INFORMATION {
    ULONG Length;
    ULONG TotalCalls;
    LARGE_INTEGER TimeOfCalls[1];
} SYSTEM_CALL_TIME_INFORMATION, *PSYSTEM_CALL_TIME_INFORMATION;

// Class 11 - See RTL_PROCESS_MODULES

// Class 12 - See RTL_PROCESS_LOCKS

// Class 13 - See RTL_PROCESS_BACKTRACES

// Class 14 - 15
typedef struct _SYSTEM_POOL_ENTRY {
    BOOLEAN Allocated;
    BOOLEAN Spare0;
    USHORT AllocatorBackTraceIndex;
    ULONG Size;
    union
    {
        UCHAR Tag[4];
        ULONG TagUlong;
        PVOID ProcessChargedQuota;
    };
} SYSTEM_POOL_ENTRY, *PSYSTEM_POOL_ENTRY;

typedef struct _SYSTEM_POOL_INFORMATION {
    SIZE_T TotalSize;
    PVOID FirstEntry;
    USHORT EntryOverhead;
    BOOLEAN PoolTagPresent;
    BOOLEAN Spare0;
    ULONG NumberOfEntries;
    SYSTEM_POOL_ENTRY Entries[1];
} SYSTEM_POOL_INFORMATION, *PSYSTEM_POOL_INFORMATION;

// Class 16
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

// Class 17
typedef struct _SYSTEM_OBJECTTYPE_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfObjects;
    ULONG NumberOfHandles;
    ULONG TypeIndex;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    ULONG PoolType;
    BOOLEAN SecurityRequired;
    BOOLEAN WaitableObject;
    UNICODE_STRING TypeName;
} SYSTEM_OBJECTTYPE_INFORMATION, *PSYSTEM_OBJECTTYPE_INFORMATION;

typedef struct _SYSTEM_OBJECT_INFORMATION {
    ULONG NextEntryOffset;
    PVOID Object;
    HANDLE CreatorUniqueProcess;
    USHORT CreatorBackTraceIndex;
    USHORT Flags;
    LONG PointerCount;
    LONG HandleCount;
    ULONG PagedPoolCharge;
    ULONG NonPagedPoolCharge;
    HANDLE ExclusiveProcessId;
    PVOID SecurityDescriptor;
    OBJECT_NAME_INFORMATION NameInfo;
} SYSTEM_OBJECT_INFORMATION, *PSYSTEM_OBJECT_INFORMATION;

// Class 18
typedef struct _SYSTEM_PAGEFILE_INFORMATION {
    ULONG NextEntryOffset;
    ULONG TotalSize;
    ULONG TotalInUse;
    ULONG PeakUsage;
    UNICODE_STRING PageFileName;
} SYSTEM_PAGEFILE_INFORMATION, *PSYSTEM_PAGEFILE_INFORMATION;

// Class 19
typedef struct _SYSTEM_VDM_INSTEMUL_INFO {
    ULONG SegmentNotPresent;
    ULONG VdmOpcode0F;
    ULONG OpcodeESPrefix;
    ULONG OpcodeCSPrefix;
    ULONG OpcodeSSPrefix;
    ULONG OpcodeDSPrefix;
    ULONG OpcodeFSPrefix;
    ULONG OpcodeGSPrefix;
    ULONG OpcodeOPER32Prefix;
    ULONG OpcodeADDR32Prefix;
    ULONG OpcodeINSB;
    ULONG OpcodeINSW;
    ULONG OpcodeOUTSB;
    ULONG OpcodeOUTSW;
    ULONG OpcodePUSHF;
    ULONG OpcodePOPF;
    ULONG OpcodeINTnn;
    ULONG OpcodeINTO;
    ULONG OpcodeIRET;
    ULONG OpcodeINBimm;
    ULONG OpcodeINWimm;
    ULONG OpcodeOUTBimm;
    ULONG OpcodeOUTWimm ;
    ULONG OpcodeINB;
    ULONG OpcodeINW;
    ULONG OpcodeOUTB;
    ULONG OpcodeOUTW;
    ULONG OpcodeLOCKPrefix;
    ULONG OpcodeREPNEPrefix;
    ULONG OpcodeREPPrefix;
    ULONG OpcodeHLT;
    ULONG OpcodeCLI;
    ULONG OpcodeSTI;
    ULONG BopCount;
} SYSTEM_VDM_INSTEMUL_INFO, *PSYSTEM_VDM_INSTEMUL_INFO;

// Class 20 - ULONG VDMBOPINFO

// Class 21
typedef struct _SYSTEM_FILECACHE_INFORMATION {
    SIZE_T CurrentSize;
    SIZE_T PeakSize;
    ULONG PageFaultCount;
    SIZE_T MinimumWorkingSet;
    SIZE_T MaximumWorkingSet;
    SIZE_T CurrentSizeIncludingTransitionInPages;
    SIZE_T PeakSizeIncludingTransitionInPages;
    ULONG TransitionRePurposeCount;
    ULONG Flags;
} SYSTEM_FILECACHE_INFORMATION, *PSYSTEM_FILECACHE_INFORMATION;

// Class 22
typedef struct _SYSTEM_POOLTAG {
    union
    {
        UCHAR Tag[4];
        ULONG TagUlong;
    };
    ULONG PagedAllocs;
    ULONG PagedFrees;
    SIZE_T PagedUsed;
    ULONG NonPagedAllocs;
    ULONG NonPagedFrees;
    SIZE_T NonPagedUsed;
} SYSTEM_POOLTAG, *PSYSTEM_POOLTAG;

typedef struct _SYSTEM_POOLTAG_INFORMATION {
    ULONG Count;
    SYSTEM_POOLTAG TagInfo[1];
} SYSTEM_POOLTAG_INFORMATION, *PSYSTEM_POOLTAG_INFORMATION;

// Class 23
typedef struct _SYSTEM_INTERRUPT_INFORMATION {
    ULONG ContextSwitches;
    ULONG DpcCount;
    ULONG DpcRate;
    ULONG TimeIncrement;
    ULONG DpcBypassCount;
    ULONG ApcBypassCount;
} SYSTEM_INTERRUPT_INFORMATION, *PSYSTEM_INTERRUPT_INFORMATION;

// Class 24
typedef struct _SYSTEM_DPC_BEHAVIOR_INFORMATION {
    ULONG Spare;
    ULONG DpcQueueDepth;
    ULONG MinimumDpcRate;
    ULONG AdjustDpcThreshold;
    ULONG IdealDpcRate;
} SYSTEM_DPC_BEHAVIOR_INFORMATION, *PSYSTEM_DPC_BEHAVIOR_INFORMATION;

// Class 25
typedef struct _SYSTEM_MEMORY_INFO {
    PUCHAR StringOffset;
    USHORT ValidCount;
    USHORT TransitionCount;
    USHORT ModifiedCount;
    USHORT PageTableCount;
} SYSTEM_MEMORY_INFO, *PSYSTEM_MEMORY_INFO;

typedef struct _SYSTEM_MEMORY_INFORMATION {
    ULONG InfoSize;
    ULONG StringStart;
    SYSTEM_MEMORY_INFO Memory[1];
} SYSTEM_MEMORY_INFORMATION, *PSYSTEM_MEMORY_INFORMATION;

// Class 26
typedef struct _SYSTEM_GDI_DRIVER_INFORMATION {
    UNICODE_STRING DriverName;
    PVOID ImageAddress;
    PVOID SectionPointer;
    PVOID EntryPoint;
    PIMAGE_EXPORT_DIRECTORY ExportSectionPointer;
    ULONG ImageLength;
} SYSTEM_GDI_DRIVER_INFORMATION, *PSYSTEM_GDI_DRIVER_INFORMATION;

// Class 27
// Not an actually class, simply a PVOID to the ImageAddress

// Class 28
typedef struct _SYSTEM_QUERY_TIME_ADJUST_INFORMATION {
    ULONG TimeAdjustment;
    ULONG TimeIncrement;
    BOOLEAN Enable;
} SYSTEM_QUERY_TIME_ADJUST_INFORMATION, *PSYSTEM_QUERY_TIME_ADJUST_INFORMATION;

typedef struct _SYSTEM_SET_TIME_ADJUST_INFORMATION {
    ULONG TimeAdjustment;
    BOOLEAN Enable;
} SYSTEM_SET_TIME_ADJUST_INFORMATION, *PSYSTEM_SET_TIME_ADJUST_INFORMATION;

// Class 29 - Same as 25

// FIXME: Class 30

// Class 31
typedef struct _SYSTEM_REF_TRACE_INFORMATION {
   UCHAR TraceEnable;
   UCHAR TracePermanent;
   UNICODE_STRING TraceProcessName;
   UNICODE_STRING TracePoolTags;
} SYSTEM_REF_TRACE_INFORMATION, *PSYSTEM_REF_TRACE_INFORMATION;

// Class 32
typedef struct _SYSTEM_BOOT_CONSOLE_INFORMATION {
    ULONG NumberOfRows;
    ULONG NumberOfColumns;
} SYSTEM_BOOT_CONSOLE_INFORMATION, *PSYSTEM_BOOT_CONSOLE_INFORMATION;

// Class 33
typedef struct _SYSTEM_EXCEPTION_INFORMATION {
    ULONG AlignmentFixupCount;
    ULONG ExceptionDispatchCount;
    ULONG FloatingEmulationCount;
    ULONG ByteWordEmulationCount;
} SYSTEM_EXCEPTION_INFORMATION, *PSYSTEM_EXCEPTION_INFORMATION;

// Class 34
typedef struct _SYSTEM_CRASH_STATE_INFORMATION {
    ULONG ValidCrashDump;
} SYSTEM_CRASH_STATE_INFORMATION, *PSYSTEM_CRASH_STATE_INFORMATION;

// Class 35
typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

// Class 36
typedef struct _SYSTEM_CONTEXT_SWITCH_INFORMATION {
    ULONG ContextSwitches;
    ULONG FindAny;
    ULONG FindLast;
    ULONG FindIdeal;
    ULONG IdleAny;
    ULONG IdleCurrent;
    ULONG IdleLast;
    ULONG IdleIdeal;
    ULONG PreemptAny;
    ULONG PreemptCurrent;
    ULONG PreemptLast;
    ULONG SwitchToIdle;
} SYSTEM_CONTEXT_SWITCH_INFORMATION, *PSYSTEM_CONTEXT_SWITCH_INFORMATION;

// Class 37
typedef struct _SYSTEM_REGISTRY_QUOTA_INFORMATION {
    ULONG RegistryQuotaAllowed;
    ULONG RegistryQuotaUsed;
    SIZE_T PagedPoolSize;
} SYSTEM_REGISTRY_QUOTA_INFORMATION, *PSYSTEM_REGISTRY_QUOTA_INFORMATION;

// Class 38
// Not a structure, simply send the UNICODE_STRING

// Class 39
// Not a structure, simply send a ULONG containing the new separation

// Class 40
typedef struct _SYSTEM_PLUGPLAY_BUS_INFORMATION {
    ULONG BusCount;
    PLUGPLAY_BUS_INSTANCE BusInstance[1];
} SYSTEM_PLUGPLAY_BUS_INFORMATION, *PSYSTEM_PLUGPLAY_BUS_INFORMATION;

// Class 41
typedef struct _SYSTEM_DOCK_INFORMATION {
    SYSTEM_DOCK_STATE DockState;
    INTERFACE_TYPE DeviceBusType;
    ULONG DeviceBusNumber;
    ULONG SlotNumber;
} SYSTEM_DOCK_INFORMATION, *PSYSTEM_DOCK_INFORMATION;

// Class 42
typedef struct _SYSTEM_POWER_INFORMATION_NATIVE {
    BOOLEAN SystemSuspendSupported;
    BOOLEAN SystemHibernateSupported;
    BOOLEAN ResumeTimerSupportsSuspend;
    BOOLEAN ResumeTimerSupportsHibernate;
    BOOLEAN LidSupported;
    BOOLEAN TurboSettingSupported;
    BOOLEAN TurboMode;
    BOOLEAN SystemAcOrDc;
    BOOLEAN PowerDownDisabled;
    LARGE_INTEGER SpindownDrives;
} SYSTEM_POWER_INFORMATION_NATIVE, *PSYSTEM_POWER_INFORMATION_NATIVE;

// Class 43
typedef struct _SYSTEM_LEGACY_DRIVER_INFORMATION {
    PNP_VETO_TYPE VetoType;
    UNICODE_STRING VetoDriver;
} SYSTEM_LEGACY_DRIVER_INFORMATION, *PSYSTEM_LEGACY_DRIVER_INFORMATION;

// Class 44
//typedef struct _TIME_ZONE_INFORMATION RTL_TIME_ZONE_INFORMATION;

// Class 45
typedef struct _SYSTEM_LOOKASIDE_INFORMATION {
    USHORT CurrentDepth;
    USHORT MaximumDepth;
    ULONG TotalAllocates;
    ULONG AllocateMisses;
    ULONG TotalFrees;
    ULONG FreeMisses;
    ULONG Type;
    ULONG Tag;
    ULONG Size;
} SYSTEM_LOOKASIDE_INFORMATION, *PSYSTEM_LOOKASIDE_INFORMATION;

// Class 46
// Not a structure. Only a HANDLE for the SlipEvent;

// Class 47
// Not a structure. Only a ULONG for the SessionId;

// Class 48
// Not a structure. Only a ULONG for the SessionId;

// FIXME: Class 49

// Class 50
// Not a structure. Only a ULONG_PTR for the SystemRangeStart

// Class 51
typedef struct _SYSTEM_VERIFIER_INFORMATION {
   ULONG NextEntryOffset;
   ULONG Level;
   UNICODE_STRING DriverName;
   ULONG RaiseIrqls;
   ULONG AcquireSpinLocks;
   ULONG SynchronizeExecutions;
   ULONG AllocationsAttempted;
   ULONG AllocationsSucceeded;
   ULONG AllocationsSucceededSpecialPool;
   ULONG AllocationsWithNoTag;
   ULONG TrimRequests;
   ULONG Trims;
   ULONG AllocationsFailed;
   ULONG AllocationsFailedDeliberately;
   ULONG Loads;
   ULONG Unloads;
   ULONG UnTrackedPool;
   ULONG CurrentPagedPoolAllocations;
   ULONG CurrentNonPagedPoolAllocations;
   ULONG PeakPagedPoolAllocations;
   ULONG PeakNonPagedPoolAllocations;
   SIZE_T PagedPoolUsageInBytes;
   SIZE_T NonPagedPoolUsageInBytes;
   SIZE_T PeakPagedPoolUsageInBytes;
   SIZE_T PeakNonPagedPoolUsageInBytes;
} SYSTEM_VERIFIER_INFORMATION, *PSYSTEM_VERIFIER_INFORMATION;

// FIXME: Class 52

// Class 53
typedef struct _SYSTEM_SESSION_PROCESS_INFORMATION {
    ULONG SessionId;
    ULONG SizeOfBuf;
    PVOID Buffer; // Same format as in SystemProcessInformation
} SYSTEM_SESSION_PROCESS_INFORMATION, *PSYSTEM_SESSION_PROCESS_INFORMATION;

// FIXME: Class 54

// Class 55
#define MAXIMUM_NUMA_NODES 16
typedef struct _SYSTEM_NUMA_INFORMATION {
    ULONG HighestNodeNumber;
    ULONG Reserved;
    union
    {
        ULONGLONG ActiveProcessorsAffinityMask[MAXIMUM_NUMA_NODES];
        ULONGLONG AvailableMemory[MAXIMUM_NUMA_NODES];
    };
} SYSTEM_NUMA_INFORMATION, *PSYSTEM_NUMA_INFORMATION;

// FIXME: Class 56-63

// Class 64
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR Count;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handle[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

// TODO: Class 65-75

/*
 * Firmware Table Actions for SystemFirmwareTableInformation
 */
typedef enum _SYSTEM_FIRMWARE_TABLE_ACTION {
    SystemFirmwareTable_Enumerate = 0,
    SystemFirmwareTable_Get = 1,
} SYSTEM_FIRMWARE_TABLE_ACTION, *PSYSTEM_FIRMWARE_TABLE_ACTION;

//
// Class 76
//
typedef struct _SYSTEM_FIRMWARE_TABLE_INFORMATION {
    ULONG ProviderSignature;
    SYSTEM_FIRMWARE_TABLE_ACTION Action;
    ULONG TableID;
    ULONG TableBufferLength;
    UCHAR TableBuffer[1];
} SYSTEM_FIRMWARE_TABLE_INFORMATION, *PSYSTEM_FIRMWARE_TABLE_INFORMATION;

// TODO: Class 77-89

// Class 90
typedef struct _SYSTEM_BOOT_ENVIRONMENT_INFORMATION {
    GUID BootIdentifier;
    FIRMWARE_TYPE FirmwareType;
    ULONGLONG BootFlags;
} SYSTEM_BOOT_ENVIRONMENT_INFORMATION, *PSYSTEM_BOOT_ENVIRONMENT_INFORMATION;

typedef struct _SYSTEM_BOOT_ENVIRONMENT_V1 {
    GUID BootIdentifier;
    FIRMWARE_TYPE FirmwareType;
} SYSTEM_BOOT_ENVIRONMENT_V1, *PSYSTEM_BOOT_ENVIRONMENT_V1;

// FIXME: Class 91-97

// Class 98
typedef struct _SYSTEM_SYSTEM_PARTITION_INFORMATION {
    UNICODE_STRING SystemPartition;
} SYSTEM_SYSTEM_PARTITION_INFORMATION, *PSYSTEM_SYSTEM_PARTITION_INFORMATION;

// Class 99
typedef struct _SYSTEM_SYSTEM_DISK_INFORMATION {
    UNICODE_STRING SystemDisk;
} SYSTEM_SYSTEM_DISK_INFORMATION, *PSYSTEM_SYSTEM_DISK_INFORMATION;

#ifndef _NTOSKRNL_
NTAPI NTSYSAPI NTSTATUS NtDisplayString(IN PCUNICODE_STRING String);

NTAPI NTSYSAPI NTSTATUS NtDisplayStringA(IN PCSTR String);

NTAPI NTSYSAPI NTSTATUS NtRaiseHardError(IN NTSTATUS ErrorStatus,
					 IN ULONG NumberOfParameters,
					 IN ULONG UnicodeStringParameterMask,
					 IN PULONG_PTR Parameters,
					 IN HARDERROR_RESPONSE_OPTION ResponseOption,
					 OUT PHARDERROR_RESPONSE Response);

NTAPI NTSYSAPI NTSTATUS NtCreateTimer(OUT PHANDLE TimerHandle,
				      IN ACCESS_MASK DesiredAccess,
				      IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
				      IN TIMER_TYPE TimerType);

NTAPI NTSYSAPI NTSTATUS NtSetTimer(IN HANDLE TimerHandle,
				   IN PLARGE_INTEGER DueTime,
				   IN PTIMER_APC_ROUTINE TimerApcRoutine,
				   IN PVOID TimerContext,
				   IN BOOLEAN WakeTimer,
				   IN OPTIONAL LONG Period,
				   OUT OPTIONAL PBOOLEAN PreviousState);

NTAPI NTSYSAPI NTSTATUS NtCancelTimer(IN HANDLE TimerHandle,
				      OUT OPTIONAL PBOOLEAN CurrentState);

NTAPI NTSYSAPI NTSTATUS NtOpenTimer(OUT PHANDLE TimerHandle,
				    IN ACCESS_MASK DesiredAccess,
				    IN POBJECT_ATTRIBUTES ObjectAttributes);

NTAPI NTSYSAPI NTSTATUS NtCreateEvent(OUT PHANDLE EventHandle,
				      IN ACCESS_MASK DesiredAccess,
				      IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
				      IN EVENT_TYPE EventType,
				      IN BOOLEAN InitialState);

NTAPI NTSYSAPI NTSTATUS NtSetEvent(IN HANDLE EventHandle,
				   OUT OPTIONAL PLONG PreviousState);

NTAPI NTSYSAPI NTSTATUS NtClearEvent(IN HANDLE EventHandle);

NTAPI NTSYSAPI NTSTATUS NtResetEvent(IN HANDLE EventHandle,
				     OUT OPTIONAL PLONG NumberOfWaitingThreads);

NTAPI NTSYSAPI NTSTATUS NtOpenEvent(OUT HANDLE *EventHandle,
				    IN ACCESS_MASK DesiredAccess,
				    IN POBJECT_ATTRIBUTES ObjectAttributes);

NTAPI NTSYSAPI NTSTATUS NtPulseEvent(IN HANDLE EventHandle,
				     IN OPTIONAL PLONG PulseCount);

NTAPI NTSYSAPI NTSTATUS NtQueryEvent(IN HANDLE EventHandle,
				     IN EVENT_INFORMATION_CLASS EventInformationClass,
				     OUT PVOID EventInformation,
				     IN ULONG EventInformationLength,
				     OUT PULONG ReturnLength);

NTAPI NTSYSAPI NTSTATUS NtCreateKeyedEvent(OUT PHANDLE KeyedEventHandle,
					   IN ACCESS_MASK DesiredAccess,
					   IN POBJECT_ATTRIBUTES ObjectAttributes,
					   IN ULONG Flags);

NTAPI NTSYSAPI NTSTATUS NtWaitForKeyedEvent(IN OPTIONAL HANDLE KeyedEventHandle,
					    IN PVOID Key,
					    IN BOOLEAN Alertable,
					    IN OPTIONAL PLARGE_INTEGER Timeout);

NTAPI NTSYSAPI NTSTATUS NtReleaseKeyedEvent(IN OPTIONAL HANDLE KeyedEventHandle,
					    IN PVOID Key,
					    IN BOOLEAN Alertable,
					    IN OPTIONAL PLARGE_INTEGER Timeout);

NTAPI NTSYSAPI NTSTATUS NtCreateMutant(OUT PHANDLE MutantHandle,
				       IN ACCESS_MASK DesiredAccess,
				       IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
				       IN BOOLEAN InitialOwner);

NTAPI NTSYSAPI NTSTATUS NtOpenMutant(OUT PHANDLE MutantHandle,
				     IN ACCESS_MASK DesiredAccess,
				     IN POBJECT_ATTRIBUTES ObjectAttributes);

NTAPI NTSYSAPI NTSTATUS NtReleaseMutant(IN HANDLE MutantHandle,
					IN OPTIONAL PLONG ReleaseCount);

NTAPI NTSYSAPI NTSTATUS NtCreateSemaphore(OUT PHANDLE SemaphoreHandle,
					  IN ACCESS_MASK DesiredAccess,
					  IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
					  IN LONG InitialCount, IN LONG MaximumCount);

NTAPI NTSYSAPI NTSTATUS NtOpenSemaphore(OUT PHANDLE SemaphoreHandle,
					IN ACCESS_MASK DesiredAccess,
					IN POBJECT_ATTRIBUTES ObjectAttributes);

NTAPI NTSYSAPI NTSTATUS NtAddAtom(IN PCUNICODE_STRING AtomName,
				  OUT PRTL_ATOM Atom);

NTAPI NTSYSAPI NTSTATUS NtReleaseSemaphore(IN HANDLE SemaphoreHandle,
					   IN LONG ReleaseCount,
					   OUT OPTIONAL PLONG PreviousCount);

NTAPI NTSYSAPI NTSTATUS NtDeleteAtom(IN RTL_ATOM Atom);

NTAPI NTSYSAPI NTSTATUS NtFindAtom(IN PCUNICODE_STRING AtomName,
				   OUT OPTIONAL PRTL_ATOM Atom);

NTAPI NTSYSAPI NTSTATUS NtQueryInformationAtom(IN RTL_ATOM Atom,
					       IN ATOM_INFORMATION_CLASS AtomInformationClass,
					       OUT PVOID AtomInformation,
					       IN ULONG AtomInformationLength,
					       OUT OPTIONAL PULONG ReturnLength);

NTAPI NTSYSAPI NTSTATUS NtSetDefaultLocale(IN BOOLEAN UserProfile,
					   IN LCID DefaultLocaleId);

NTAPI NTSYSAPI NTSTATUS NtQueryDefaultLocale(IN BOOLEAN UserProfile,
					     OUT PLCID DefaultLocaleId);

NTAPI NTSYSAPI NTSTATUS NtQueryDefaultUILanguage(OUT LANGID *LanguageId);

NTAPI NTSYSAPI NTSTATUS NtQueryInstallUILanguage(OUT LANGID* LanguageId);

NTAPI NTSYSAPI NTSTATUS NtSetSystemInformation(IN SYSTEM_INFORMATION_CLASS InfoClass,
					       IN PVOID SystemInformation,
					       IN ULONG SystemInformationLength);

NTAPI NTSYSAPI NTSTATUS NtQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS InfoClass,
						 OUT PVOID SystemInformation,
						 IN ULONG SystemInformationLength,
						 OUT OPTIONAL PULONG ReturnLength);

NTAPI NTSYSAPI NTSTATUS NtQuerySystemEnvironmentValueEx(IN PCUNICODE_STRING VariableName,
							IN LPGUID VendorGuid,
							OUT OPTIONAL PVOID Value,
							IN OUT PULONG ReturnLength,
							OUT OPTIONAL PULONG Attributes);

NTAPI NTSYSAPI NTSTATUS NtSetSystemEnvironmentValueEx(IN PCUNICODE_STRING VariableName,
						      IN LPGUID VendorGuid,
						      IN OPTIONAL PVOID Value,
						      IN ULONG ValueLength,
						      IN ULONG Attributes);

NTAPI NTSYSAPI NTSTATUS NtShutdownSystem(IN SHUTDOWN_ACTION Action);

#endif
