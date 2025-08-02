/*
 * storport.h
 *
 * StorPort interface
 *
 * This file is part of the w32api package.
 *
 * Contributors:
 *   Created by Casper S. Hornstrup <chorns@users.sourceforge.net>
 *
 * THIS SOFTWARE IS NOT COPYRIGHTED
 *
 * This source code is offered for use in the public domain. You may
 * use, modify or distribute it freely.
 *
 * This code is distributed in the hope that it will be useful but
 * WITHOUT ANY WARRANTY. ALL WARRANTIES, EXPRESS OR IMPLIED ARE HEREBY
 * DISCLAIMED. This includes but is not limited to warranties of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

#include <ntddk.h>
#include <hal.h>
#include <scsi.h>
#include <srb.h>

#ifndef _NTSTORPORT_
#define _NTSTORPORT_

/*
 * Storage port driver status codes
 * This is the storage equivalent of NTSTATUS
 */
#define STOR_STATUS_SUCCESS                     (0x00000000L)
#define STOR_STATUS_UNSUCCESSFUL                (0xC1000001L)
#define STOR_STATUS_NOT_IMPLEMENTED             (0xC1000002L)
#define STOR_STATUS_INSUFFICIENT_RESOURCES      (0xC1000003L)
#define STOR_STATUS_BUFFER_TOO_SMALL            (0xC1000004L)
#define STOR_STATUS_ACCESS_DENIED               (0xC1000005L)
#define STOR_STATUS_INVALID_PARAMETER           (0xC1000006L)
#define STOR_STATUS_INVALID_DEVICE_REQUEST      (0xC1000007L)
#define STOR_STATUS_INVALID_IRQL                (0xC1000008L)
#define STOR_STATUS_INVALID_DEVICE_STATE        (0xC1000009L)
#define STOR_STATUS_INVALID_BUFFER_SIZE         (0xC100000AL)
#define STOR_STATUS_UNSUPPORTED_VERSION         (0xC100000BL)
#define STOR_STATUS_BUSY                        (0xC100000CL)

typedef PHYSICAL_ADDRESS STOR_PHYSICAL_ADDRESS, *PSTOR_PHYSICAL_ADDRESS;

typedef struct _ACCESS_RANGE {
    STOR_PHYSICAL_ADDRESS RangeStart;
    ULONG RangeLength;
    BOOLEAN RangeInMemory;
} ACCESS_RANGE, *PACCESS_RANGE;

/*
 * Represents a region of physically contiguous memory.
 */
typedef struct _MEMORY_REGION {
    PUCHAR VirtualBase;
    PHYSICAL_ADDRESS PhysicalBase;
    ULONG Length;
} MEMORY_REGION, *PMEMORY_REGION;

typedef enum _STOR_SYNCHRONIZATION_MODEL {
    StorSynchronizeHalfDuplex,
    StorSynchronizeFullDuplex
} STOR_SYNCHRONIZATION_MODEL;

typedef enum _INTERRUPT_SYNCHRONIZATION_MODE {
    InterruptSupportNone,
    InterruptSynchronizeAll,
    InterruptSynchronizePerMessage
} INTERRUPT_SYNCHRONIZATION_MODE;

typedef BOOLEAN HW_MESSAGE_SIGNALED_INTERRUPT_ROUTINE (IN PVOID HwDeviceExtension,
						       IN ULONG MessageId);
typedef HW_MESSAGE_SIGNALED_INTERRUPT_ROUTINE *PHW_MESSAGE_SIGNALED_INTERRUPT_ROUTINE;


typedef struct _PORT_CONFIGURATION_INFORMATION {
    ULONG Length;
    ULONG SystemIoBusNumber;
    INTERFACE_TYPE AdapterInterfaceType;
    ULONG BusInterruptLevel;
    ULONG BusInterruptVector;
    KINTERRUPT_MODE InterruptMode;
    ULONG MaximumTransferLength;
    ULONG NumberOfPhysicalBreaks;
    ULONG DmaChannel;
    ULONG DmaPort;
    DMA_WIDTH DmaWidth;
    DMA_SPEED DmaSpeed;
    ULONG AlignmentMask;
    ULONG NumberOfAccessRanges;
    ACCESS_RANGE (*AccessRanges)[];
    PVOID MiniportDumpData;
    UCHAR NumberOfBuses;
    UCHAR InitiatorBusId[8];
    BOOLEAN ScatterGather;
    BOOLEAN Master;
    BOOLEAN CachesData;
    BOOLEAN AdapterScansDown;
    BOOLEAN AtdiskPrimaryClaimed;
    BOOLEAN AtdiskSecondaryClaimed;
    BOOLEAN Dma32BitAddresses;
    BOOLEAN DemandMode;
    BOOLEAN MapBuffers;
    BOOLEAN NeedPhysicalAddresses;
    BOOLEAN TaggedQueuing;
    BOOLEAN AutoRequestSense;
    BOOLEAN MultipleRequestPerLu;
    BOOLEAN ReceiveEvent;
    BOOLEAN RealModeInitialized;
    BOOLEAN BufferAccessScsiPortControlled;
    UCHAR MaximumNumberOfTargets;
    UCHAR ReservedUchars[2];
    ULONG SlotNumber;
    ULONG BusInterruptLevel2;
    ULONG BusInterruptVector2;
    KINTERRUPT_MODE InterruptMode2;
    ULONG DmaChannel2;
    ULONG DmaPort2;
    DMA_WIDTH DmaWidth2;
    DMA_SPEED DmaSpeed2;
    ULONG DeviceExtensionSize;
    ULONG SpecificLuExtensionSize;
    ULONG SrbExtensionSize;
    UCHAR Dma64BitAddresses;
    BOOLEAN ResetTargetSupported;
    UCHAR MaximumNumberOfLogicalUnits;
    BOOLEAN WmiDataProvider;
    STOR_SYNCHRONIZATION_MODEL SynchronizationModel;
    PHW_MESSAGE_SIGNALED_INTERRUPT_ROUTINE HwMSInterruptRoutine;
    INTERRUPT_SYNCHRONIZATION_MODE InterruptSynchronizationMode;
    MEMORY_REGION DumpRegion;
    ULONG RequestedDumpBufferSize;
    BOOLEAN VirtualDevice;
    UCHAR DumpMode;
    ULONG ExtendedFlags1;
    ULONG MaxNumberOfIO;
    ULONG MaxIOsPerLun;
    ULONG InitialLunQueueDepth;
    ULONG BusResetHoldTime;         // in usec
    ULONG FeatureSupport;
} PORT_CONFIGURATION_INFORMATION, *PPORT_CONFIGURATION_INFORMATION;

#define CONFIG_INFO_VERSION_2 sizeof(PORT_CONFIGURATION_INFORMATION)

/*
 * Flags for PORT_CONFIGURATION_INFORMATION::FeatureSupport
 */
// Indicating the miniport driver supports storage device telemetry
#define STOR_ADAPTER_FEATURE_DEVICE_TELEMETRY               0x00000001
// Indicating the adapter wants STOP_UNIT command during system shutdown
#define STOR_ADAPTER_FEATURE_STOP_UNIT_DURING_POWER_DOWN    0x00000002
// Indicating that miniport driver wants UncachedExtension to be allocated
// from adapter NUMA node.
#define STOR_ADAPTER_UNCACHED_EXTENSION_NUMA_NODE_PREFERRED 0x00000004
// Indicating that miniport driver prefers to use DMA V3 kernel API for
// the adapter.
#define STOR_ADAPTER_DMA_V3_PREFERRED                       0x00000008
// Indicating the miniport driver supports the ability to abort an outstanding
// command via SRB_FUNCTION_ABORT_COMMAND.
#define STOR_ADAPTER_FEATURE_ABORT_COMMAND                  0x00000010
// Indicating the adapter supports richer temperature threshold information
// than defined in SCSI SPC4 spec.
#define STOR_ADAPTER_FEATURE_RICH_TEMPERATURE_THRESHOLD     0x00000020
// Indicating the miniport driver specified the DMA address width in
// DmaAddressWidth for the adapter. Added in Windows 10, version 2004.
#define STOR_ADAPTER_DMA_ADDRESS_WIDTH_SPECIFIED            0x00000040

/* Values for PORT_CONFIGURATION_INFORMATION::DumpMode */
#define DUMP_MODE_CRASH         0x01    // crashdump
#define DUMP_MODE_HIBER         0x02    // hibernation
#define DUMP_MODE_MARK_MEMORY   0x03    // memory marking only
#define DUMP_MODE_RESUME        0x04    // resume from hibernation

#define STOR_MAP_NO_BUFFERS (0)
#define STOR_MAP_ALL_BUFFERS (1)
#define STOR_MAP_NON_READ_WRITE_BUFFERS (2)
#define STOR_MAP_ALL_BUFFERS_INCLUDING_READ_WRITE (3)

/* Bit flags for the ChangedEntity parameter of StorPortStateChangeDetected */
#define STATE_CHANGE_LUN        0x1
#define STATE_CHANGE_TARGET     0x2
#define STATE_CHANGE_BUS        0x4

#define MINIPORT_REG_SZ         1
#define MINIPORT_REG_BINARY     3
#define MINIPORT_REG_DWORD      4
#define MINIPORT_REG_MULTI_SZ   7

typedef enum _STOR_DMA_WIDTH {
    DmaUnknown,
    Dma32Bit,
    Dma64BitScatterGather,
    Dma64Bit
} STOR_DMA_WIDTH;

typedef enum _STOR_SPINLOCK { DpcLock = 1, StartIoLock, InterruptLock } STOR_SPINLOCK;

typedef enum _STORPORT_FUNCTION_CODE {
    ExtFunctionAllocatePool,
    ExtFunctionFreePool,
    ExtFunctionAllocateMdl,
    ExtFunctionFreeMdl,
    ExtFunctionBuildMdlForNonPagedPool,
    ExtFunctionGetSystemAddress,
    ExtFunctionGetOriginalMdl,
    ExtFunctionCompleteServiceIrp,
    ExtFunctionGetDeviceObjects,
    ExtFunctionBuildScatterGatherList,
    ExtFunctionPutScatterGatherList,
    ExtFunctionAcquireMSISpinLock,
    ExtFunctionReleaseMSISpinLock,
    ExtFunctionGetMessageInterruptInformation,
    ExtFunctionInitializePerformanceOptimizations,
    ExtFunctionGetStartIoPerformanceParameters,
    ExtFunctionLogSystemEvent,
    ExtFunctionGetCurrentProcessorNumber,
    ExtFunctionGetActiveGroupCount,
    ExtFunctionGetGroupAffinity,
    ExtFunctionGetActiveNodeCount,
    ExtFunctionGetNodeAffinity,
    ExtFunctionGetHighestNodeNumber,
    ExtFunctionGetLogicalProcessorRelationship,
    ExtFunctionAllocateContiguousMemorySpecifyCacheNode,
    ExtFunctionFreeContiguousMemorySpecifyCache,
    ExtFunctionSetPowerSettingNotificationGuids,
    ExtFunctionInvokeAcpiMethod,
    ExtFunctionGetRequestInfo,
    ExtFunctionInitializeWorker,
    ExtFunctionQueueWorkItem,
    ExtFunctionFreeWorker,
    ExtFunctionInitializeTimer,
    ExtFunctionRequestTimer,
    ExtFunctionFreeTimer,
    ExtFunctionInitializeSListHead,
    ExtFunctionInterlockedFlushSList,
    ExtFunctionInterlockedPopEntrySList,
    ExtFunctionInterlockedPushEntrySList,
    ExtFunctionQueryDepthSList,
    ExtFunctionGetActivityId,
    ExtFunctionGetSystemPortNumber,
    ExtFunctionGetDataInBufferMdl,
    ExtFunctionGetDataInBufferSystemAddress,
    ExtFunctionGetDataInBufferScatterGatherList,
    ExtFunctionMarkDumpMemory,
    ExtFunctionSetUnitAttributes,
    ExtFunctionQueryPerformanceCounter,
    ExtFunctionInitializePoFxPower,
    ExtFunctionPoFxActivateComponent,
    ExtFunctionPoFxIdleComponent,
    ExtFunctionPoFxSetComponentLatency,
    ExtFunctionPoFxSetComponentResidency,
    ExtFunctionPoFxPowerControl,
    ExtFunctionFlushDataBufferMdl,
    ExtFunctionDeviceOperationAllowed,
    ExtFunctionGetProcessorIndexFromNumber,
    ExtFunctionPoFxSetIdleTimeout,
    ExtFunctionMiniportEtwEvent2,
    ExtFunctionMiniportEtwEvent4,
    ExtFunctionMiniportEtwEvent8,
    ExtFunctionCurrentOsInstallationUpgrade,
    ExtFunctionRegistryReadAdapterKey,
    ExtFunctionRegistryWriteAdapterKey,
    ExtFunctionSetAdapterBusType,
    ExtFunctionPoFxRegisterPerfStates,
    ExtFunctionPoFxSetPerfState,
    ExtFunctionGetD3ColdSupport,
    ExtFunctionInitializeRpmb,
    ExtFunctionAllocateHmb,
    ExtFunctionFreeHmb,
    ExtFunctionPropagateIrpExtension
} STORPORT_FUNCTION_CODE, *PSTORPORT_FUNCTION_CODE;

typedef enum _STOR_EVENT_ASSOCIATION_ENUM {
    StorEventAdapterAssociation = 0,
    StorEventLunAssociation,
    StorEventTargetAssociation,
    StorEventInvalidAssociation
} STOR_EVENT_ASSOCIATION_ENUM;

typedef enum _GETSGSTATUS {
    SG_ALLOCATED = 0,
    SG_BUFFER_TOO_SMALL
} GETSGSTATUS, *PGETSGSTATUS;

/*
 * Command type (and parameter) definition(s) for UnitControl requests.
 */
typedef enum _SCSI_UNIT_CONTROL_TYPE {
    ScsiQuerySupportedUnitControlTypes,
    ScsiUnitUsage,
    ScsiUnitStart,
    ScsiUnitPower,
    ScsiUnitPoFxPowerInfo,
    ScsiUnitPoFxPowerRequired,
    ScsiUnitPoFxPowerActive,
    ScsiUnitPoFxPowerSetFState,
    ScsiUnitPoFxPowerControl,
    ScsiUnitRemove,
    ScsiUnitSurpriseRemoval,
    ScsiUnitRichDescription,
    ScsiUnitQueryBusType,
    ScsiUnitQueryFruId,
    ScsiUnitReportInternalData,
    ScsiUnitKsrPowerDown,
    ScsiUnitNvmeIceInformation,
    ScsiUnitControlMax,
    MakeUnitControlTypeSizeOfUlong
} SCSI_UNIT_CONTROL_TYPE, *PSCSI_UNIT_CONTROL_TYPE;

/*
 * Unit control status values
 */
typedef enum _SCSI_UNIT_CONTROL_STATUS {
    ScsiUnitControlSuccess = 0,
    ScsiUnitControlUnsuccessful
} SCSI_UNIT_CONTROL_STATUS, *PSCSI_UNIT_CONTROL_STATUS;

/*
 * A common header for both adapter and unit control parameters.
 * For units, Address will point to a STOR_ADDRESS structure.
 * For adapters, Address will be NULL.
 */
typedef struct _STOR_POWER_CONTROL_HEADER {
    ULONG Version;
    ULONG Size;
    PSTOR_ADDRESS Address;
} STOR_POWER_CONTROL_HEADER, *PSTOR_POWER_CONTROL_HEADER;

/*
 * Parameter to miniport driver with ScsiPowerSettingNotification
 */
typedef struct _STOR_POWER_SETTING_INFO {
    GUID    PowerSettingGuid;
    _Field_size_bytes_(ValueLength) PVOID Value;
    ULONG   ValueLength;
} STOR_POWER_SETTING_INFO, *PSTOR_POWER_SETTING_INFO;

//
// Parameter to miniport driver for ScsiAdapterPower.
// This will only be invoked if the miniport has opted-in to runtime power
// management for the adapter.  The miniport will not receive an
// SRB_FUNCTION_POWER request in this case.  This informs the miniport of
// D-state transitions.  For runtime D-state transitions, PowerAction will be
// StorPowerActionNone.
//
typedef struct _STOR_ADAPTER_CONTROL_POWER {
    STOR_POWER_CONTROL_HEADER   Header;
    STOR_POWER_ACTION           PowerAction;
    STOR_DEVICE_POWER_STATE     PowerState;
} STOR_ADAPTER_CONTROL_POWER, *PSTOR_ADAPTER_CONTROL_POWER;

//
// Parameter to miniport driver for ScsiUnitPower.
// If this is a runtime D-state transition, the PowerAction will be
// StorPowerActionNone.
//
typedef struct _STOR_UNIT_CONTROL_POWER {
    PSTOR_ADDRESS               Address;
    STOR_POWER_ACTION           PowerAction;
    STOR_DEVICE_POWER_STATE     PowerState;
} STOR_UNIT_CONTROL_POWER, *PSTOR_UNIT_CONTROL_POWER;

typedef enum _RAID_SYSTEM_POWER {
    RaidSystemPowerUnknown,
    RaidSystemPowerLowest,
    RaidSystemPowerLow,
    RaidSystemPowerMedium,
    RaidSystemPowerHigh
} RAID_SYSTEM_POWER, *PRAID_SYSTEM_POWER;

//
// Parameter to miniport driver for ScsiAdapterSystemPowerHints.
// This is invoked on Always-On Always Connected (AoAC) systems to
// provide system power hints to miniports.
//
typedef struct _STOR_SYSTEM_POWER_HINTS {
    ULONG Version;
    ULONG Size;

    RAID_SYSTEM_POWER SystemPower;

    //
    // The maximum resume latency tolerated for the given system power hint.
    //
    ULONG ResumeLatencyMSec;

} STOR_SYSTEM_POWER_HINTS, *PSTOR_SYSTEM_POWER_HINTS;

#define STOR_SYSTEM_POWER_HINTS_V1 0x1

//
// Parameter to miniport driver for ScsiUnitPoFxPowerInfo.
//
typedef struct _STOR_POFX_UNIT_POWER_INFO {
    STOR_POWER_CONTROL_HEADER   Header;
    BOOLEAN                 IdlePowerEnabled;
} STOR_POFX_UNIT_POWER_INFO, *PSTOR_POFX_UNIT_POWER_INFO;

//
// Parameters common to Unit and Adapter Control Functions:
//

//
// Parameter to miniport driver for Scsi(Adapter/Unit)PoFxPowerRequired.
// The PowerRequired field indicates if power is (TRUE) or is not (FALSE)
// required for the adapter or unit.
//
typedef struct _STOR_POFX_POWER_REQUIRED_CONTEXT {
    STOR_POWER_CONTROL_HEADER Header;
    BOOLEAN                   PowerRequired;
} STOR_POFX_POWER_REQUIRED_CONTEXT, *PSTOR_POFX_POWER_REQUIRED_CONTEXT;

//
// Parameter to miniport driver for Scsi(Adapter/Unit)PoFxPowerActive and
// Scsi(Adapter/Unit)PoFxPowerIdle.
// This will only be invoked if the miniport has opted-in to runtime power
// management for the adapter/unit.  This notifies the miniport that the given
// component is now in the runtime active (Active == TRUE) or idle
// (Active == FALSE) state.
// ComponentIndex is the index of the component to which this applies.
//
typedef struct _STOR_POFX_ACTIVE_CONTEXT {
    STOR_POWER_CONTROL_HEADER   Header;
    ULONG                       ComponentIndex;
    BOOLEAN                     Active;
} STOR_POFX_ACTIVE_CONTEXT, *PSTOR_POFX_ACTIVE_CONTEXT;

//
// Parameter to miniport driver for Scsi(Adapter/Unit)FxPowerSetFState.
// This will only be invoked if the miniport has opted-in to runtime power
// management for the adapter/unit.  This notifies the miniport that the given
// component should do the work necessary to transition it into the given
// F-state.  The miniport should not complete this Adapter/Unit Control request
// until it has completed the F-state transition.
// ComponentIndex is the index of the component to which this applies.
// FState is the F-state to which the component should transition.
//
typedef struct _STOR_POFX_FSTATE_CONTEXT {
    STOR_POWER_CONTROL_HEADER   Header;
    ULONG                       ComponentIndex;
    ULONG                       FState;
} STOR_POFX_FSTATE_CONTEXT, *PSTOR_POFX_FSTATE_CONTEXT;

//
// Parameter to miniport driver for Scsi(Adapter/Unit)FxPowerControl.
// This will only be invoked if the miniport has opted-in to runtime power
// management for the adapter/unit.  This is invoked by the PEP only if the PEP
// and miniport have defined a private power interface; otherwise, the miniport
// will never see this invoked.
//
typedef struct _STOR_POFX_POWER_CONTROL {
    STOR_POWER_CONTROL_HEADER   Header;
    LPCGUID                     PowerControlCode;
    SIZE_T                      InBufferSize;
    SIZE_T                      OutBufferSize;
    PVOID                       InBuffer;
    PVOID                       OutBuffer;
    PSIZE_T                     BytesReturned;
} STOR_POFX_POWER_CONTROL, *PSTOR_POFX_POWER_CONTROL;

typedef struct _STOR_SCATTER_GATHER_ELEMENT {
    STOR_PHYSICAL_ADDRESS PhysicalAddress;
    ULONG Length;
    ULONG_PTR Reserved;
} STOR_SCATTER_GATHER_ELEMENT, *PSTOR_SCATTER_GATHER_ELEMENT;

typedef struct _STOR_SCATTER_GATHER_LIST {
    ULONG NumberOfElements;
    ULONG_PTR Reserved;
    STOR_SCATTER_GATHER_ELEMENT List[];
} STOR_SCATTER_GATHER_LIST, *PSTOR_SCATTER_GATHER_LIST;

typedef struct _DPC_BUFFER {
    CSHORT Type;
    UCHAR Number;
    UCHAR Importance;
    struct {
	PVOID F;
	PVOID B;
    };
    PVOID DeferredRoutine;
    PVOID DeferredContext;
    PVOID SystemArgument1;
    PVOID SystemArgument2;
    PVOID DpcData;
} DPC_BUFFER;

typedef struct _STOR_DPC {
    DPC_BUFFER Dpc;
} STOR_DPC, *PSTOR_DPC;

typedef struct _STOR_LOCK_HANDLE {
    STOR_SPINLOCK Lock;
    struct {
	struct {
	    PVOID Next;
	    PVOID Lock;
	} LockQueue;
	KIRQL OldIrql;
    } Context;
} STOR_LOCK_HANDLE, *PSTOR_LOCK_HANDLE;

typedef struct _STOR_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWCH   Buffer;
} STOR_UNICODE_STRING, *PSTOR_UNICODE_STRING;

typedef enum _STOR_IO_PRIORITY_HINT {
    StorIoPriorityVeryLow = 0,
    StorIoPriorityLow,
    StorIoPriorityNormal,
    StorIoPriorityHigh,
    StorIoPriorityCritical,
    StorIoMaxPriorityTypes,
    StorIoMaxPriorityValue = 0xffff
} STOR_IO_PRIORITY_HINT, *PSTOR_IO_PRIORITY_HINT;

#define STOR_REQUEST_INFO_VER_1         1
#define STOR_REQUEST_INFO_VER_2         2
#define STOR_REQUEST_INFO_VER           STOR_REQUEST_INFO_VER_2

typedef struct _STOR_REQUEST_INFO_V1 {
    USHORT Version;
    USHORT Size;
    STOR_IO_PRIORITY_HINT PriorityHint;
    ULONG Flags;
    ULONG Key;
    ULONG Length;
    BOOLEAN IsWriteRequest;
    UCHAR Reserved[3];
} STOR_REQUEST_INFO_V1, *PSTOR_REQUEST_INFO_V1;

typedef struct _STOR_REQUEST_INFO_V2 {
    USHORT Version;
    USHORT Size;
    STOR_IO_PRIORITY_HINT PriorityHint;
    ULONG Flags;
    ULONG Key;
    ULONG Length;
    BOOLEAN IsWriteRequest;
    UCHAR Reserved[3];

    //
    // Caller should access the below unicode string
    // buffer only at IRQL < DISPATCH level and
    // only during the lifetime of the SRB request.
    // Caller must not try to update or free it.
    //

    PSTOR_UNICODE_STRING FileName;
    ULONG ProcessId;
} STOR_REQUEST_INFO_V2, *PSTOR_REQUEST_INFO_V2;

typedef STOR_REQUEST_INFO_V2 STOR_REQUEST_INFO, *PSTOR_REQUEST_INFO;

typedef struct _STOR_LOG_EVENT_DETAILS {
    ULONG InterfaceRevision;
    ULONG Size;
    ULONG Flags;
    STOR_EVENT_ASSOCIATION_ENUM EventAssociation;
    ULONG PathId;
    ULONG TargetId;
    ULONG LunId;
    BOOLEAN StorportSpecificErrorCode;
    ULONG ErrorCode;
    ULONG UniqueId;
    ULONG DumpDataSize;
    PVOID DumpData;
    ULONG StringCount;
    PWSTR *StringList;
} STOR_LOG_EVENT_DETAILS, *PSTOR_LOG_EVENT_DETAILS;

//
// Storage perf optimizations
//
#define STOR_PERF_DPC_REDIRECTION 0x00000001
#define STOR_PERF_CONCURRENT_CHANNELS 0x00000002

// Optimizations supported in STOR_PERF_VERSION_2
#define STOR_PERF_INTERRUPT_MESSAGE_RANGES 0x00000004

// Optimizations supported in STOR_PERF_VERSION_3
#define STOR_PERF_ADV_CONFIG_LOCALITY 0x00000008
#define STOR_PERF_OPTIMIZE_FOR_COMPLETION_DURING_STARTIO 0x00000010

// Optimizations supported in STOR_PERF_VERSION_4
#define STOR_PERF_DPC_REDIRECTION_CURRENT_CPU 0x00000020

//
// STOR_PERF_VERSION supported and current STOR_PERF_VERSION
//
#define STOR_PERF_VERSION_2 0x00000002
#define STOR_PERF_VERSION_3 0x00000003
#define STOR_PERF_VERSION_4 0x00000004

#define STOR_PERF_VERSION STOR_PERF_VERSION_4

typedef struct _PERF_CONFIGURATION_DATA {
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG ConcurrentChannels;
    ULONG FirstRedirectionMessageNumber;
    ULONG LastRedirectionMessageNumber;
    ULONG DeviceNode;
    ULONG Reserved;
    PGROUP_AFFINITY MessageTargets;
} PERF_CONFIGURATION_DATA, *PPERF_CONFIGURATION_DATA;

typedef struct _STARTIO_PERFORMANCE_PARAMETERS {
    ULONG Version;
    ULONG Size;
    ULONG MessageNumber;
    ULONG ChannelNumber;
} STARTIO_PERFORMANCE_PARAMETERS, *PSTARTIO_PERFORMANCE_PARAMETERS;

typedef struct _MESSAGE_INTERRUPT_INFORMATION {
    ULONG MessageId;
    ULONG MessageData;
    STOR_PHYSICAL_ADDRESS MessageAddress;
    ULONG InterruptVector;
    ULONG InterruptLevel;
    KINTERRUPT_MODE InterruptMode;
} MESSAGE_INTERRUPT_INFORMATION, *PMESSAGE_INTERRUPT_INFORMATION;

/*
 * Runtime Power Management Data Structures and Functions
 */

/*
 * Defines an F-State for a STOR_POFX_COMPONENT
 */
typedef struct _STOR_POFX_COMPONENT_IDLE_STATE {
    ULONG     Version;
    ULONG     Size;
    ULONGLONG TransitionLatency;
    ULONGLONG ResidencyRequirement;
    ULONG     NominalPower;
} STOR_POFX_COMPONENT_IDLE_STATE, *PSTOR_POFX_COMPONENT_IDLE_STATE;

#define STOR_POFX_COMPONENT_IDLE_STATE_SIZE (sizeof(STOR_POFX_COMPONENT_IDLE_STATE))
#define STOR_POFX_COMPONENT_IDLE_STATE_VERSION_V1 1

#define STOR_POFX_UNKNOWN_POWER 0xFFFFFFFF
#define STOR_POFX_UNKNOWN_TIME  0xFFFFFFFFFFFFFFFF

/*
 * Defines a component of a STOR_POFX_DEVICE
 */
typedef struct _STOR_POFX_COMPONENT {
    ULONG                          Version;
    ULONG                          Size;
    ULONG                          FStateCount;
    ULONG                          DeepestWakeableFState;
    GUID                           Id;
    STOR_POFX_COMPONENT_IDLE_STATE FStates[ANYSIZE_ARRAY];
} STOR_POFX_COMPONENT, *PSTOR_POFX_COMPONENT;

#define STOR_POFX_COMPONENT_SIZE ((ULONG)FIELD_OFFSET(STOR_POFX_COMPONENT, FStates))
#define STOR_POFX_COMPONENT_VERSION_V1 1

/*
 * Defines a component of a STOR_POFX_DEVICE(_V2).
 */
typedef struct _STOR_POFX_COMPONENT_V2 {
    ULONG Version;
    ULONG Size;
    ULONG FStateCount;
    ULONG DeepestWakeableFState;
    GUID Id;
    ULONG DeepestAdapterPowerRequiredFState;
    ULONG DeepestCrashDumpReadyFState;
    STOR_POFX_COMPONENT_IDLE_STATE FStates[ANYSIZE_ARRAY];
} STOR_POFX_COMPONENT_V2, *PSTOR_POFX_COMPONENT_V2;

#define STOR_POFX_COMPONENT_V2_SIZE ((ULONG)FIELD_OFFSET(STOR_POFX_COMPONENT_V2, FStates))
#define STOR_POFX_COMPONENT_VERSION_V2 2

typedef enum _STOR_POFX_PERF_STATE_UNIT {
    StorPoFxPerfStateUnitOther,
    StorPoFxPerfStateUnitFrequency,
    StorPoFxPerfStateUnitBandwidth,
    StorPoFxPerfStateUnitMilliwatts,
    StorPoFxPerfStateUnitMaximum
} STOR_POFX_PERF_STATE_UNIT, *PSTOR_POFX_PERF_STATE_UNIT;

typedef enum _STOR_POFX_PERF_STATE_TYPE {
    StorPoFxPerfStateTypeDiscrete,
    StorPoFxPerfStateTypeRange,
    StorPoFxPerfStateTypeMaximum
} STOR_POFX_PERF_STATE_TYPE, *PSTOR_POFX_PERF_STATE_TYPE;

//
// Perf state structure for discrete power states.
//
typedef struct _STOR_POFX_PERF_STATE {
    ULONG Version;
    ULONG Size;
    ULONGLONG Value;    // The value associated with this P-State.
    PVOID Context;      // Any additional context that isn't represented in Value.
} STOR_POFX_PERF_STATE, *PSTOR_POFX_PERF_STATE;

#define STOR_POFX_PERF_STATE_SIZE (sizeof(STOR_POFX_PERF_STATE))
#define STOR_POFX_PERF_STATE_VERSION_V1 1

typedef struct _STOR_POFX_COMPONENT_PERF_SET {
    ULONG Version;
    ULONG Size;
    ULONGLONG Flags;
    STOR_POFX_PERF_STATE_UNIT PStateUnit;
    STOR_POFX_PERF_STATE_TYPE PStateType;
    union {
        struct {
            ULONG Count;
            ULONG Offset;
        } Discrete;
        struct {
            ULONGLONG Minimum;
            ULONGLONG Maximum;
        } Range;
    } PStates;
} STOR_POFX_COMPONENT_PERF_SET, *PSTOR_POFX_COMPONENT_PERF_SET;

#define STOR_POFX_COMPONENT_PERF_SET_SIZE (sizeof(STOR_POFX_COMPONENT_PERF_SET))
#define STOR_POFX_COMPONENT_PERF_SET_VERSION_V1 1

#define STOR_POFX_COMPONENT_MIN_PERF_SETS 0
#define STOR_POFX_COMPONENT_MAX_PERF_SETS 3
#define STOR_POFX_MIN_DISCRETE_PERF_STATES 1
#define STOR_POFX_MAX_DISCRETE_PERF_STATES 8

#define STOR_POFX_UNIT_MIN_IDLE_STATES 1
#define STOR_POFX_UNIT_MAX_IDLE_STATES 2

#define STOR_POFX_ADAPTER_MIN_IDLE_STATES 1
#define STOR_POFX_ADAPTER_MAX_IDLE_STATES 8

static const GUID STORPORT_POFX_ADAPTER_GUID = {
    0xdcaf9c10, 0x895f, 0x481f, { 0xa4, 0x92, 0xd4, 0xce, 0xd2, 0xf5, 0x56, 0x33 }
};
static const GUID STORPORT_POFX_LUN_GUID = {
    0x585d326b, 0xb3a, 0x4088, { 0x89, 0x39, 0x88, 0xb0, 0xf, 0x69, 0x58, 0xbe }
};

//
// STOR_POFX_DEVICE defines a device to be runtime power-managed and should be
// used to register a device when calling StorPortInitializeFxPower().
//
typedef struct _STOR_POFX_DEVICE {
    ULONG Version;
    ULONG Size;
    ULONG ComponentCount;
    ULONG Flags;
    _Field_size_full_(ComponentCount) STOR_POFX_COMPONENT Components[ANYSIZE_ARRAY];
} STOR_POFX_DEVICE, *PSTOR_POFX_DEVICE;

#define STOR_POFX_DEVICE_SIZE ((ULONG)FIELD_OFFSET(STOR_POFX_DEVICE, Components))
#define STOR_POFX_DEVICE_VERSION_V1 1

typedef struct _STOR_POFX_DEVICE_V2 {
    ULONG               Version;
    ULONG               Size;
    ULONG               ComponentCount;
    ULONG               Flags;
    union {
	ULONG UnitMinIdleTimeoutInMS;
	ULONG AdapterIdleTimeoutInMS;
    };
    STOR_POFX_COMPONENT Components[ANYSIZE_ARRAY];
} STOR_POFX_DEVICE_V2, *PSTOR_POFX_DEVICE_V2;

#define STOR_POFX_DEVICE_V2_SIZE ((ULONG)FIELD_OFFSET(STOR_POFX_DEVICE_V2, Components))
#define STOR_POFX_DEVICE_VERSION_V2 2

typedef struct _STOR_POFX_DEVICE_V3 {
    ULONG               Version;
    ULONG               Size;
    ULONG               ComponentCount;
    ULONG               Flags;
    union {
	ULONG UnitMinIdleTimeoutInMS;
	ULONG AdapterIdleTimeoutInMS;
    };
    ULONG               MinimumPowerCyclePeriodInMS;
    STOR_POFX_COMPONENT Components[ANYSIZE_ARRAY];
} STOR_POFX_DEVICE_V3, *PSTOR_POFX_DEVICE_V3;

#define STOR_POFX_DEVICE_V3_SIZE ((ULONG)FIELD_OFFSET(STOR_POFX_DEVICE_V3, Components))
#define STOR_POFX_DEVICE_VERSION_V3 3

//
// A miniport must only specify one component for a unit.
//
#define STOR_POFX_UNIT_MIN_COMPONENTS 1
#define STOR_POFX_UNIT_MAX_COMPONENTS 1

//
// A miniport must only specify one component for an adapter.
//
#define STOR_POFX_ADAPTER_MIN_COMPONENTS 1
#define STOR_POFX_ADAPTER_MAX_COMPONENTS 1

//
// A miniport can specify these flags when registering a STOR_POFX_DEVICE to opt
// in or out of certain Storport behaviors.
//
// STOR_POFX_DEVICE_FLAG_NO_D0 - If a miniport sets this flag, Storport will
//  *not* request a D0 when its PO_FX_DEVICE_POWER_REQUIRED_CALLBACK is invoked.
//  Instead, Storport will notify the miniport that device power is required via
//  StorPortAdapterPowerRequired() or StorPortUnitPowerRequired().
#define STOR_POFX_DEVICE_FLAG_NO_D0                     0x01
// STOR_POFX_DEVICE_FLAG_NO_D3 - If a miniport sets this flag, Storport will
//  *not* request a D3 when its PO_FX_DEVICE_POWER_NOT_REQUIRED_CALLBACK is invoked.
//  Instead, Storport will notify the miniport that device power is not required via
//  StorPortAdapterPowerNotRequired() or StorPortUnitPowerNotRequired().
#define STOR_POFX_DEVICE_FLAG_NO_D3                     0x02
// STOR_POFX_DEVICE_FLAG_ENABLE_D3_COLD - This flag is only relevant for adapters.
//  If a miniport sets this flag, Storport will enable D3Cold for the adapter if
//  the platform supports it.
#define STOR_POFX_DEVICE_FLAG_ENABLE_D3_COLD            0x04
// STOR_POFX_DEVICE_FLAG_NO_DUMP_ACTIVE - If a miniport sets this flag, it
//  indicates that the dump version of miniport is not capable of bringing device
//  to active if device was put into either the idle state or power off state
//  (D3Cold).
//  This allows system to determine if device can be used for dump if device is idle.
//  NOTE: If STOR_POFX_COMPONENT_V2 is used, this flag does not apply to the idle
//  condition; it only applies to D3Cold.
#define STOR_POFX_DEVICE_FLAG_NO_DUMP_ACTIVE            0x08
// STOR_POFX_DEVICE_FLAG_IDLE_TIMEOUT - Indicates if the UnitMinIdleTimeoutInMS or
//  AdapterIdleTimeoutInMS values should be used in the STOR_POFX_DEVICE_V2
//  structure.
#define STOR_POFX_DEVICE_FLAG_IDLE_TIMEOUT              0x10
// STOR_POFX_DEVICE_FLAG_ADAPTIVE_D3_IDLE_TIMEOUT - Only valid if STOR_POFX_DEVICE_V3
//  is used.  Indicates that Storport should dynamically adjust the D3 idle timeout
//  such that the device can aggressively enter D3 when necessary.
#define STOR_POFX_DEVICE_FLAG_ADAPTIVE_D3_IDLE_TIMEOUT  0x20
// STOR_POFX_DEVICE_FLAG_NO_UNIT_REGISTRATION - Specifies that none of the units
//  exposed by this adapter should be registered for runtime power management.
//  Valid only for STOR_POFX_DEVICEs that represent an adapter.
#define STOR_POFX_DEVICE_FLAG_NO_UNIT_REGISTRATION      0x40
// STOR_POFX_DEVICE_FLAG_PERF_STATE_PEP_OPTIONAL - Indicates the miniport does not
//  require P-State support from the PEP.  When in doubt, set this flag.
#define STOR_POFX_DEVICE_FLAG_PERF_STATE_PEP_OPTIONAL   0x80
// STOR_POFX_DEVICE_FLAG_NO_IDLE_DEBOUNCE - Indicates the miniport wants to opt-out
//  of Active/Idle debouncing.  Without this flag the runtime power management
//  framework will apply some debouncing to Active/Idle transitions.  This flag
//  disables that and means the miniport will get an Idle condition callback much
//  more quickly after the active references on the device go from 1 to 0.
//  A miniport should only set this flag if it needs an Idle condition callback
//  within 500ms of going idle.
#define STOR_POFX_DEVICE_FLAG_NO_IDLE_DEBOUNCE          0x100
// STOR_POFX_DEVICE_FLAG_DUMP_ALWAYS_POWER_ON - Indicates the dump stack should
//  always attempt to power on the device regardless of its logical power state.
//  This can be useful if there are physical entities behind the registered
//  logical entity and one or more of those physical entities need powering up
//  (via the PEP).  This supersedes STOR_POFX_DEVICE_FLAG_NO_DUMP_ACTIVE.
#define STOR_POFX_DEVICE_FLAG_DUMP_ALWAYS_POWER_ON      0x200
// The miniport would like Storport to disable/ enable interrupts on Dx transitions.
#define STOR_POFX_DEVICE_FLAG_DISABLE_INTERRUPTS_ON_D3  0x400
// The miniport isopt-in adapter D3 wake support.
#define STOR_POFX_DEVICE_FLAG_ADAPTER_D3_WAKE           0x800
// The miniport requires P-states from the PEP.
#define STOR_POFX_DEVICE_FLAG_GET_PERF_STATE_FROM_PEP  0x1000

//
// Storport interfaces to allow miniports to log ETW events.
//
typedef enum _STORPORT_ETW_LEVEL {
    StorportEtwLevelLogAlways = 0,
    StorportEtwLevelCritical = 1,
    StorportEtwLevelError = 2,
    StorportEtwLevelWarning = 3,
    StorportEtwLevelInformational = 4,
    StorportEtwLevelVerbose = 5,
    StorportEtwLevelMax = StorportEtwLevelVerbose
} STORPORT_ETW_LEVEL, *PSTORPORT_ETW_LEVEL;

//
// These keyword bits can be OR'd together to specify more than one keyword.
//
#define STORPORT_ETW_EVENT_KEYWORD_IO           0x01
#define STORPORT_ETW_EVENT_KEYWORD_PERFORMANCE  0x02
#define STORPORT_ETW_EVENT_KEYWORD_POWER        0x04
#define STORPORT_ETW_EVENT_KEYWORD_ENUMERATION  0x08
#define STORPORT_ETW_EVENT_KEYWORD_COMMAND_TRACE 0x10

typedef enum _STORPORT_ETW_EVENT_OPCODE {
    StorportEtwEventOpcodeInfo = 0,
    StorportEtwEventOpcodeStart = 1,
    StorportEtwEventOpcodeStop = 2,
    StorportEtwEventOpcodeDC_Start = 3,
    StorportEtwEventOpcodeDC_Stop = 4,
    StorportEtwEventOpcodeExtension = 5,
    StorportEtwEventOpcodeReply = 6,
    StorportEtwEventOpcodeResume = 7,
    StorportEtwEventOpcodeSuspend = 8,
    StorportEtwEventOpcodeSend = 9,
    StorportEtwEventOpcodeReceive = 240
} STORPORT_ETW_EVENT_OPCODE, *PSTORPORT_ETW_EVENT_OPCODE;

//
// The event description must not exceed 32 characters and the parameter
// names must not exceed 16 characters (not including the NULL terminator).
//
#define STORPORT_ETW_MAX_DESCRIPTION_LENGTH 32
#define STORPORT_ETW_MAX_PARAM_NAME_LENGTH 16

typedef enum _STORPORT_ETW_EVENT_CHANNEL {
    StorportEtwEventDiagnostic,
    StorportEtwEventOperational,
    StorportEtwEventHealth,
    StorportEtwEventIoPerformance
} STORPORT_ETW_EVENT_CHANNEL, *PSTORPORT_ETW_EVENT_CHANNEL;

#define STORPORT_ETW_EVENT_KEYWORD_IO           0x01
#define STORPORT_ETW_EVENT_KEYWORD_PERFORMANCE  0x02
#define STORPORT_ETW_EVENT_KEYWORD_POWER        0x04
#define STORPORT_ETW_EVENT_KEYWORD_ENUMERATION  0x08

#define EVENT_BUFFER_MAX_LENGTH     4096
#define EVENT_NAME_MAX_LENGTH       32
#define EVENT_MAX_PARAM_NAME_LEN    32

typedef struct _STORPORT_TELEMETRY_EVENT {
    ULONG     DriverVersion;
    ULONG     EventId;
    UCHAR     EventName[EVENT_NAME_MAX_LENGTH];
    ULONG     EventVersion;
    ULONG     Flags;
    ULONG     EventBufferLength;
    PUCHAR    EventBuffer;
    UCHAR     ParameterName0[EVENT_MAX_PARAM_NAME_LEN];
    ULONGLONG ParameterValue0;
    UCHAR     ParameterName1[EVENT_MAX_PARAM_NAME_LEN];
    ULONGLONG ParameterValue1;
    UCHAR     ParameterName2[EVENT_MAX_PARAM_NAME_LEN];
    ULONGLONG ParameterValue2;
    UCHAR     ParameterName3[EVENT_MAX_PARAM_NAME_LEN];
    ULONGLONG ParameterValue3;
    UCHAR     ParameterName4[EVENT_MAX_PARAM_NAME_LEN];
    ULONGLONG ParameterValue4;
    UCHAR     ParameterName5[EVENT_MAX_PARAM_NAME_LEN];
    ULONGLONG ParameterValue5;
    UCHAR     ParameterName6[EVENT_MAX_PARAM_NAME_LEN];
    ULONGLONG ParameterValue6;
    UCHAR     ParameterName7[EVENT_MAX_PARAM_NAME_LEN];
    ULONGLONG ParameterValue7;
} STORPORT_TELEMETRY_EVENT, *PSTORPORT_TELEMETRY_EVENT;

FORCEINLINE ULONG StorPortLogTelemetry(IN PVOID HwDeviceExtension,
				       IN OPTIONAL PSTOR_ADDRESS StorAddress,
				       IN PSTORPORT_TELEMETRY_EVENT Event)
{
    return STOR_STATUS_NOT_IMPLEMENTED;
}

#define DUMP_MINIPORT_VERSION_1         0x0100
#define DUMP_MINIPORT_VERSION           0x0200
#define DUMP_MINIPORT_NAME_LENGTH       15

typedef struct _MINIPORT_DUMP_POINTERS {
    USHORT Version;
    USHORT Size;
    WCHAR DriverName[DUMP_MINIPORT_NAME_LENGTH];
    struct _ADAPTER_OBJECT *AdapterObject;
    PVOID MappedRegisterBase;
    ULONG CommonBufferSize;
    PVOID MiniportPrivateDumpData;
    ULONG SystemIoBusNumber;
    INTERFACE_TYPE AdapterInterfaceType;
    ULONG MaximumTransferLength;
    ULONG NumberOfPhysicalBreaks;
    ULONG AlignmentMask;
    ULONG NumberOfAccessRanges;
    ACCESS_RANGE (*AccessRanges)[];
    UCHAR NumberOfBuses;
    BOOLEAN  Master;
    BOOLEAN MapBuffers;
    UCHAR MaximumNumberOfTargets;
} MINIPORT_DUMP_POINTERS, *PMINIPORT_DUMP_POINTERS;

typedef BOOLEAN (NTAPI HW_INITIALIZE)(IN PVOID DeviceExtension);
typedef HW_INITIALIZE *PHW_INITIALIZE;

typedef BOOLEAN (NTAPI HW_BUILDIO)(IN PVOID DeviceExtension,
				   IN PSCSI_REQUEST_BLOCK Srb);
typedef HW_BUILDIO *PHW_BUILDIO;

typedef BOOLEAN (NTAPI HW_STARTIO)(IN PVOID DeviceExtension,
				   IN PSCSI_REQUEST_BLOCK Srb);
typedef HW_STARTIO *PHW_STARTIO;

typedef BOOLEAN (NTAPI HW_INTERRUPT)(IN PVOID DeviceExtension);
typedef HW_INTERRUPT *PHW_INTERRUPT;

typedef VOID (NTAPI HW_TIMER)(IN PVOID DeviceExtension);
typedef HW_TIMER *PHW_TIMER;

typedef VOID HW_TIMER_EX(IN PVOID DeviceExtension,
			 IN OPTIONAL PVOID Context);
typedef HW_TIMER_EX *PHW_TIMER_EX;

typedef VOID HW_WORKITEM(IN PVOID HwDeviceExtension,
			 IN OPTIONAL PVOID Context,
			 IN PVOID Worker);
typedef HW_WORKITEM *PHW_WORKITEM;

typedef VOID HW_STATE_CHANGE(IN PVOID HwDeviceExtension,
			     IN OPTIONAL PVOID Context,
			     IN SHORT AddressType,
			     IN PVOID Address,
			     IN ULONG Status);
typedef HW_STATE_CHANGE *PHW_STATE_CHANGE;

typedef VOID (NTAPI HW_DMA_STARTED)(IN PVOID DeviceExtension);
typedef HW_DMA_STARTED *PHW_DMA_STARTED;

typedef ULONG (NTAPI HW_FIND_ADAPTER)(IN PVOID DeviceExtension, IN PVOID HwContext,
				      IN PVOID BusInformation, IN PCHAR ArgumentString,
				      IN OUT PPORT_CONFIGURATION_INFORMATION ConfigInfo,
				      OUT PBOOLEAN Again);
typedef HW_FIND_ADAPTER *PHW_FIND_ADAPTER;

typedef BOOLEAN (NTAPI HW_RESET_BUS)(IN PVOID DeviceExtension, IN ULONG PathId);
typedef HW_RESET_BUS *PHW_RESET_BUS;

typedef BOOLEAN (NTAPI HW_ADAPTER_STATE)(IN PVOID DeviceExtension, IN PVOID Context,
					 IN BOOLEAN SaveState);
typedef HW_ADAPTER_STATE *PHW_ADAPTER_STATE;

typedef SCSI_ADAPTER_CONTROL_STATUS (NTAPI HW_ADAPTER_CONTROL)(IN PVOID DeviceExtension,
							       IN SCSI_ADAPTER_CONTROL_TYPE ControlType,
							       IN PVOID Parameters);
typedef HW_ADAPTER_CONTROL *PHW_ADAPTER_CONTROL;

typedef BOOLEAN (HW_PASSIVE_INITIALIZE_ROUTINE)(IN PVOID DeviceExtension);
typedef HW_PASSIVE_INITIALIZE_ROUTINE *PHW_PASSIVE_INITIALIZE_ROUTINE;

typedef VOID (HW_DPC_ROUTINE)(IN PSTOR_DPC Dpc, IN PVOID HwDeviceExtension,
			      IN PVOID SystemArgument1, IN PVOID SystemArgument2);
typedef HW_DPC_ROUTINE *PHW_DPC_ROUTINE;

typedef VOID HW_FREE_ADAPTER_RESOURCES (IN PVOID DeviceExtension);
typedef HW_FREE_ADAPTER_RESOURCES *PHW_FREE_ADAPTER_RESOURCES;

typedef VOID HW_PROCESS_SERVICE_REQUEST (IN PVOID DeviceExtension,
					 IN PVOID Irp);
typedef HW_PROCESS_SERVICE_REQUEST *PHW_PROCESS_SERVICE_REQUEST;

typedef VOID HW_COMPLETE_SERVICE_IRP (IN PVOID DeviceExtension);
typedef HW_COMPLETE_SERVICE_IRP *PHW_COMPLETE_SERVICE_IRP;

typedef VOID HW_INITIALIZE_TRACING (IN PVOID Arg1,
				    IN PVOID Arg2);
typedef HW_INITIALIZE_TRACING *PHW_INITIALIZE_TRACING;

typedef VOID HW_CLEANUP_TRACING(IN PVOID Arg1);
typedef HW_CLEANUP_TRACING *PHW_CLEANUP_TRACING;

typedef VOID (HW_TRACING_ENABLED)(PVOID HwDeviceExtension,
				  IN BOOLEAN Enabled);
typedef HW_TRACING_ENABLED *PHW_TRACING_ENABLED;

typedef SCSI_UNIT_CONTROL_STATUS (HW_UNIT_CONTROL)(IN PVOID DeviceExtension,
						   IN SCSI_UNIT_CONTROL_TYPE ControlType,
						   IN PVOID Parameters);
typedef HW_UNIT_CONTROL *PHW_UNIT_CONTROL;

typedef BOOLEAN (NTAPI STOR_SYNCHRONIZED_ACCESS)(IN PVOID HwDeviceExtension,
						 IN PVOID Context);
typedef STOR_SYNCHRONIZED_ACCESS *PSTOR_SYNCHRONIZED_ACCESS;

typedef VOID (NTAPI *PpostScaterGatherExecute)(IN PVOID *DeviceObject, IN PVOID *Irp,
					       IN PSTOR_SCATTER_GATHER_LIST ScatterGather,
					       IN PVOID Context);

typedef BOOLEAN (NTAPI *PStorPortGetMessageInterruptInformation)(IN PVOID HwDeviceExtension,
								 IN ULONG MessageId,
								 OUT PMESSAGE_INTERRUPT_INFORMATION InterruptInfo);

typedef VOID (NTAPI *PStorPortPutScatterGatherList)(IN PVOID HwDeviceExtension,
						    IN PSTOR_SCATTER_GATHER_LIST ScatterGatherList,
						    IN BOOLEAN WriteToDevice);

typedef GETSGSTATUS (NTAPI *PStorPortBuildScatterGatherList)(IN PVOID HwDeviceExtension,
							     IN PVOID Mdl,
							     IN PVOID CurrentVa,
							     IN ULONG Length,
							     IN PpostScaterGatherExecute Routine,
							     IN PVOID Context,
							     IN BOOLEAN WriteToDevice,
							     IN OUT PVOID ScatterGatherBuffer,
							     IN ULONG ScatterGatherBufferLength);

typedef VOID (NTAPI *PStorPortFreePool)(IN PVOID PMemory, IN PVOID HwDeviceExtension,
					IN OPTIONAL PVOID PMdl);

typedef PVOID (NTAPI *PStorPortAllocatePool)(IN ULONG NumberOfBytes, IN ULONG Tag,
					     IN PVOID HwDeviceExtension,
					     OUT PVOID *PMdl);

typedef PVOID (NTAPI *PStorPortGetSystemAddress)(IN PSCSI_REQUEST_BLOCK Srb);

typedef struct _STORPORT_EXTENDED_FUNCTIONS {
    ULONG Version;
    PStorPortGetMessageInterruptInformation GetMessageInterruptInformation;
    PStorPortPutScatterGatherList PutScatterGatherList;
    PStorPortBuildScatterGatherList BuildScatterGatherList;
    PStorPortFreePool FreePool;
    PStorPortAllocatePool AllocatePool;
    PStorPortGetSystemAddress GetSystemAddress;
} STORPORT_EXTENDED_FUNCTIONS, *PSTORPORT_EXTENDED_FUNCTIONS;

typedef struct _HW_INITIALIZATION_DATA {
    ULONG HwInitializationDataSize;
    INTERFACE_TYPE  AdapterInterfaceType;
    PHW_INITIALIZE HwInitialize;
    PHW_STARTIO HwStartIo;
    PHW_INTERRUPT HwInterrupt;
    PHW_FIND_ADAPTER HwFindAdapter;
    PHW_RESET_BUS HwResetBus;
    PHW_DMA_STARTED HwDmaStarted;
    PHW_ADAPTER_STATE HwAdapterState;
    ULONG DeviceExtensionSize;
    ULONG SpecificLuExtensionSize;
    ULONG SrbExtensionSize;
    ULONG NumberOfAccessRanges;
    PVOID Reserved;
    UCHAR MapBuffers;
    BOOLEAN NeedPhysicalAddresses;
    BOOLEAN TaggedQueuing;
    BOOLEAN AutoRequestSense;
    BOOLEAN MultipleRequestPerLu;
    BOOLEAN ReceiveEvent;
    USHORT VendorIdLength;
    PVOID VendorId;
    USHORT ReservedUshort;
    USHORT DeviceIdLength;
    PVOID DeviceId;
    PHW_ADAPTER_CONTROL HwAdapterControl;
    PHW_BUILDIO HwBuildIo;

    /* The following five callbacks are virtual miniport specific and
     * should not be set by physical miniports. */
    PHW_FREE_ADAPTER_RESOURCES  HwFreeAdapterResources;
    PHW_PROCESS_SERVICE_REQUEST HwProcessServiceRequest;
    PHW_COMPLETE_SERVICE_IRP    HwCompleteServiceIrp;
    PHW_INITIALIZE_TRACING      HwInitializeTracing;
    PHW_CLEANUP_TRACING         HwCleanupTracing;


    PHW_TRACING_ENABLED HwTracingEnabled;

    /* Used to indicate features supported by miniport such as virtual miniports */
    ULONG FeatureSupport;

    /* New fields added to support extended SRB format(s) */
    ULONG SrbTypeFlags;
    ULONG AddressTypeFlags;
    ULONG Reserved1;

    /* Unit control callback */
    PHW_UNIT_CONTROL  HwUnitControl;
} HW_INITIALIZATION_DATA, *PHW_INITIALIZATION_DATA;

/*
 * FeatureSupport flags in HW_INITIALIZATION_DATA to indicate features
 * supported by the miniport driver
 */
// Indicating it's a virtual miniport driver
#define STOR_FEATURE_VIRTUAL_MINIPORT                       0x00000001
// Indicating the miniport driver supports ATA PASS THROUGH (16)
#define STOR_FEATURE_ATA_PASS_THROUGH                       0x00000002
// Indicating the miniport driver fills in complete information in
// STOR_DEVICE_CAPABILITIES
#define STOR_FEATURE_FULL_PNP_DEVICE_CAPABILITIES           0x00000004
// Indicating physical miniport driver support the dump pointers SRBs
#define STOR_FEATURE_DUMP_POINTERS                          0x00000008
// Indicating the miniport driver does not want the suffix "SCSI <type> Device"
// in device friendly name
#define STOR_FEATURE_DEVICE_NAME_NO_SUFFIX                  0x00000010
// Indicating the miniport driver is resume capable (i.e. dump stack functions
// after a hibernation resume)
#define STOR_FEATURE_DUMP_RESUME_CAPABLE                    0x00000020
// Indicating that port driver forms STORAGE_DEVICE_DESCRIPTOR from ATA
// Information VPD page rather than INQUIRY data
#define STOR_FEATURE_DEVICE_DESCRIPTOR_FROM_ATA_INFO_VPD    0x00000040
// Indicating that miniport driver wants SRBEX_DATA_IO_INFO in a SRBEX if available
#define STOR_FEATURE_EXTRA_IO_INFORMATION                   0x00000080
// Indicating that miniport driver can safely process AdapterControl call
// from Storport before receiving HwFindAdapter.
#define STOR_FEATURE_ADAPTER_CONTROL_PRE_FINDADAPTER        0x00000100
// Indicating that miniport driver doesn't require IO Port resource for its adapter
#define STOR_FEATURE_ADAPTER_NOT_REQUIRE_IO_PORT            0x00000200
// Indicating the miniport driver wants its HwDeviceExtension to be 16 byte aligned
// in dump mode.
#define STOR_FEATURE_DUMP_16_BYTE_ALIGNMENT                 0x00000400
// Indicating the miniport wants Storport to set the adapter interface type
#define STOR_FEATURE_SET_ADAPTER_INTERFACE_TYPE             0x00000800
// Indicating the miniport driver supports the dump info SRBs
#define STOR_FEATURE_DUMP_INFO                              0x00001000
// Indicating the miniport driver supports to allocate DMA to physical memory without
// boundaries.
#define STOR_FEATURE_DMA_ALLOCATION_NO_BOUNDARY             0x00002000
// Indicating the miniport driver supports NVMe based Storage Adapters.
#define STOR_FEATURE_SUPPORTS_NVME_ADAPTER                  0x00004000
// Indicating the miniport driver supports reporting internal data.
#define STOR_FEATURE_REPORT_INTERNAL_DATA                   0x00008000
// Indicating the miniport driver supports early crash dump generation.
#define STOR_FEATURE_EARLY_DUMP                             0x00010000
// Indicating the miniport driver supports NVMe ICE.
#define STOR_FEATURE_NVME_ICE                               0x00020000

/*
 * SrbTypeFlags in HW_INITIALIZATION_DATA to indicate the SRB type(s)
 * supported by the miniport driver
 */
#define SRB_TYPE_FLAG_SCSI_REQUEST_BLOCK        0x1
#define SRB_TYPE_FLAG_STORAGE_REQUEST_BLOCK     0x2

typedef enum _SCSI_NOTIFICATION_TYPE {
    RequestComplete,
    NextRequest,
    NextLuRequest,
    ResetDetected,
    _obsolete1,
    _obsolete2,
    RequestTimerCall,
    BusChangeDetected,
    WMIEvent,
    WMIReregister,
    LinkUp,
    LinkDown,
    QueryTickCount,
    BufferOverrunDetected,
    TraceNotification,
    GetExtendedFunctionTable,
    EnablePassiveInitialization = 0x1000,
    InitializeDpc,
    IssueDpc,
    AcquireSpinLock,
    ReleaseSpinLock,
    StateChangeDetectedCall,    // Added in Win8
    IoTargetRequestServiceTime,
    AsyncNotificationDetected
} SCSI_NOTIFICATION_TYPE, *PSCSI_NOTIFICATION_TYPE;

//
// Define bit flags for the Flags parameter of StorPortAsyncNotificationDetected.
//
#define RAID_ASYNC_NOTIFY_FLAG_MEDIA_STATUS        0x1
#define RAID_ASYNC_NOTIFY_FLAG_DEVICE_STATUS       0x2
#define RAID_ASYNC_NOTIFY_FLAG_DEVICE_OPERATION    0x4

//
// Structure used with StorPortSetUnitAttributes
//
typedef struct _STOR_UNIT_ATTRIBUTES {
    ULONG   DeviceAttentionSupported : 1;
    ULONG   AsyncNotificationSupported: 1;
    ULONG   D3ColdNotSupported : 1;
    ULONG   Reserved : 29;
} STOR_UNIT_ATTRIBUTES, *PSTOR_UNIT_ATTRIBUTES;

#define StorPortCopyMemory(Destination, Source, Length) \
    memcpy((Destination), (Source), (Length))

#ifdef _STORPORT_
#define STORPORT_API
#else
#define STORPORT_API DECLSPEC_IMPORT
#endif

NTAPI STORPORT_API PUCHAR StorPortAllocateRegistryBuffer(IN PVOID HwDeviceExtension,
							 IN PULONG Length);

NTAPI STORPORT_API BOOLEAN StorPortBusy(IN PVOID HwDeviceExtension,
					IN ULONG RequestsToComplete);

NTAPI STORPORT_API VOID StorPortCompleteRequest(IN PVOID HwDeviceExtension,
						IN UCHAR PathId,
						IN UCHAR TargetId,
						IN UCHAR Lun,
						IN UCHAR SrbStatus);

NTAPI STORPORT_API ULONG64 StorPortConvertPhysicalAddressToUlong64(IN STOR_PHYSICAL_ADDRESS Address);

NTAPI STORPORT_API STOR_PHYSICAL_ADDRESS StorPortConvertUlong64ToPhysicalAddress(IN ULONG64 UlongAddress);

__cdecl STORPORT_API VOID StorPortDebugPrint(IN ULONG DebugPrintLevel,
					     IN PCCHAR DebugMessage, ...);

NTAPI STORPORT_API BOOLEAN StorPortDeviceBusy(IN PVOID HwDeviceExtension,
					      IN UCHAR PathId,
					      IN UCHAR TargetId,
					      IN UCHAR Lun,
					      IN ULONG RequestsToComplete);

NTAPI STORPORT_API BOOLEAN StorPortDeviceReady(IN PVOID HwDeviceExtension,
					       IN UCHAR PathId,
					       IN UCHAR TargetId,
					       IN UCHAR Lun);

NTAPI STORPORT_API VOID StorPortFreeDeviceBase(IN PVOID HwDeviceExtension,
					       IN PVOID MappedAddress);

NTAPI STORPORT_API VOID StorPortFreeRegistryBuffer(IN PVOID HwDeviceExtension,
						   IN PUCHAR Buffer);

NTAPI STORPORT_API ULONG StorPortGetBusData(IN PVOID DeviceExtension,
					    IN ULONG BusDataType,
					    IN ULONG SystemIoBusNumber,
					    IN ULONG SlotNumber,
					    OUT PVOID Buffer,
					    IN ULONG Length);

NTAPI STORPORT_API PVOID StorPortGetDeviceBase(IN PVOID HwDeviceExtension,
					       IN INTERFACE_TYPE BusType,
					       IN ULONG SystemIoBusNumber,
					       IN STOR_PHYSICAL_ADDRESS IoAddress,
					       IN ULONG NumberOfBytes,
					       IN BOOLEAN InIoSpace);

NTAPI STORPORT_API PVOID StorPortGetLogicalUnit(IN PVOID HwDeviceExtension,
						IN UCHAR PathId,
						IN UCHAR TargetId,
						IN UCHAR Lun);

NTAPI STORPORT_API STOR_PHYSICAL_ADDRESS StorPortGetPhysicalAddress(IN PVOID HwDeviceExtension,
								    IN OPTIONAL PSCSI_REQUEST_BLOCK Srb,
								    IN PVOID VirtualAddress,
								    OUT ULONG *Length);

NTAPI STORPORT_API PSTOR_SCATTER_GATHER_LIST StorPortGetScatterGatherList(IN PVOID DeviceExtension,
									  IN PSCSI_REQUEST_BLOCK Srb);

NTAPI STORPORT_API PSCSI_REQUEST_BLOCK StorPortGetSrb(IN PVOID DeviceExtension,
						      IN UCHAR PathId,
						      IN UCHAR TargetId,
						      IN UCHAR Lun,
						      IN LONG QueueTag);

NTAPI STORPORT_API PVOID StorPortGetUncachedExtension(IN PVOID HwDeviceExtension,
						      IN PPORT_CONFIGURATION_INFORMATION Info,
						      IN ULONG NumberOfBytes);

NTAPI STORPORT_API PVOID StorPortGetVirtualAddress(IN PVOID HwDeviceExtension,
						   IN STOR_PHYSICAL_ADDRESS PhysicalAddress);

NTAPI STORPORT_API ULONG StorPortInitialize(IN PVOID Argument1,
					    IN PVOID Argument2,
					    IN PHW_INITIALIZATION_DATA HwInitializationData,
					    IN OPTIONAL PVOID Unused);

NTAPI STORPORT_API VOID StorPortLogError(IN PVOID HwDeviceExtension,
					 IN OPTIONAL PSCSI_REQUEST_BLOCK Srb,
					 IN UCHAR PathId,
					 IN UCHAR TargetId,
					 IN UCHAR Lun,
					 IN ULONG ErrorCode,
					 IN ULONG UniqueId);

NTAPI STORPORT_API VOID StorPortMoveMemory(OUT PVOID WriteBuffer,
					   IN PVOID ReadBuffer,
					   IN ULONG Length);

__cdecl STORPORT_API VOID StorPortNotification(IN SCSI_NOTIFICATION_TYPE NotificationType,
					       IN PVOID HwDeviceExtension, ...);

NTAPI STORPORT_API VOID StorPortQuerySystemTime(OUT PLARGE_INTEGER CurrentTime);

NTAPI STORPORT_API ULONG StorPortAllocateDmaMemory(IN PVOID HwDeviceExtension,
						   IN SIZE_T NumberOfBytes,
						   IN PHYSICAL_ADDRESS LowestAddress,
						   IN PHYSICAL_ADDRESS HighestAddress,
						   IN OPTIONAL PHYSICAL_ADDRESS AddressMultiple,
						   IN MEMORY_CACHING_TYPE CacheType,
						   IN NODE_REQUIREMENT PreferredNode,
						   OUT PVOID *BufferPointer,
						   OUT PPHYSICAL_ADDRESS PhysicalAddress);

NTAPI STORPORT_API ULONG StorPortFreeDmaMemory(IN PVOID HwDeviceExtension,
					       IN PVOID BaseAddress,
					       IN SIZE_T NumberOfBytes,
					       IN MEMORY_CACHING_TYPE CacheType,
					       IN OPTIONAL PHYSICAL_ADDRESS PhysicalAddress);

NTAPI STORPORT_API BOOLEAN StorPortPause(IN PVOID HwDeviceExtension,
					 IN ULONG TimeOut);

NTAPI STORPORT_API BOOLEAN StorPortPauseDevice(IN PVOID HwDeviceExtension,
					       IN UCHAR PathId,
					       IN UCHAR TargetId,
					       IN UCHAR Lun,
					       IN ULONG TimeOut);

NTAPI STORPORT_API VOID StorPortReadPortBufferUchar(IN PVOID HwDeviceExtension,
						    IN PUCHAR Port,
						    IN PUCHAR Buffer,
						    IN ULONG Count);

NTAPI STORPORT_API VOID StorPortReadPortBufferUlong(IN PVOID HwDeviceExtension,
						    IN PULONG Port,
						    IN PULONG Buffer,
						    IN ULONG Count);

NTAPI STORPORT_API VOID StorPortReadPortBufferUshort(IN PVOID HwDeviceExtension,
						     IN PUSHORT Port,
						     IN PUSHORT Buffer,
						     IN ULONG Count);

NTAPI STORPORT_API UCHAR StorPortReadPortUchar(IN PVOID HwDeviceExtension,
					       IN PUCHAR Port);

NTAPI STORPORT_API ULONG StorPortReadPortUlong(IN PVOID HwDeviceExtension,
					       IN PULONG Port);

NTAPI STORPORT_API USHORT StorPortReadPortUshort(IN PVOID HwDeviceExtension,
						 IN PUSHORT Port);

NTAPI STORPORT_API VOID StorPortReadRegisterBufferUchar(IN PVOID HwDeviceExtension,
							IN PUCHAR Register,
							IN PUCHAR Buffer,
							IN ULONG Count);

NTAPI STORPORT_API VOID StorPortReadRegisterBufferUlong(IN PVOID HwDeviceExtension,
							IN PULONG Register,
							IN PULONG Buffer,
							IN ULONG Count);

NTAPI STORPORT_API VOID StorPortReadRegisterBufferUshort(IN PVOID HwDeviceExtension,
							 IN PUSHORT Register,
							 IN PUSHORT Buffer,
							 IN ULONG Count);

NTAPI STORPORT_API UCHAR StorPortReadRegisterUchar(IN PVOID HwDeviceExtension,
						   IN PUCHAR Register);

NTAPI STORPORT_API ULONG StorPortReadRegisterUlong(IN PVOID HwDeviceExtension,
						   IN PULONG Register);

NTAPI STORPORT_API USHORT StorPortReadRegisterUshort(IN PVOID HwDeviceExtension,
						     IN PUSHORT Register);

NTAPI STORPORT_API BOOLEAN StorPortReady(IN PVOID HwDeviceExtension);

NTAPI STORPORT_API BOOLEAN StorPortRegistryRead(IN PVOID HwDeviceExtension,
						IN PUCHAR ValueName,
						IN ULONG Global,
						IN ULONG Type,
						IN PUCHAR Buffer,
						IN PULONG BufferLength);

NTAPI STORPORT_API BOOLEAN StorPortRegistryWrite(IN PVOID HwDeviceExtension,
						 IN PUCHAR ValueName,
						 IN ULONG Global,
						 IN ULONG Type,
						 IN PUCHAR Buffer,
						 IN ULONG BufferLength);

NTAPI STORPORT_API BOOLEAN StorPortResume(IN PVOID HwDeviceExtension);

NTAPI STORPORT_API BOOLEAN StorPortResumeDevice(IN PVOID HwDeviceExtension,
						IN UCHAR PathId,
						IN UCHAR TargetId,
						IN UCHAR Lun);

NTAPI STORPORT_API ULONG StorPortSetBusDataByOffset(IN PVOID DeviceExtension,
						    IN ULONG BusDataType,
						    IN ULONG SystemIoBusNumber,
						    IN ULONG SlotNumber,
						    IN PVOID Buffer,
						    IN ULONG Offset,
						    IN ULONG Length);

NTAPI STORPORT_API BOOLEAN StorPortSetDeviceQueueDepth(IN PVOID HwDeviceExtension,
						       IN UCHAR PathId,
						       IN UCHAR TargetId,
						       IN UCHAR Lun,
						       IN ULONG Depth);

NTAPI STORPORT_API VOID StorPortStallExecution(IN ULONG Delay);

NTAPI STORPORT_API VOID StorPortSynchronizeAccess(IN PVOID HwDeviceExtension,
						  IN PSTOR_SYNCHRONIZED_ACCESS Routine,
						  IN OPTIONAL PVOID Context);

NTAPI STORPORT_API BOOLEAN StorPortValidateRange(IN PVOID HwDeviceExtension,
						 IN INTERFACE_TYPE BusType,
						 IN ULONG SystemIoBusNumber,
						 IN STOR_PHYSICAL_ADDRESS IoAddress,
						 IN ULONG NumberOfBytes,
						 IN BOOLEAN InIoSpace);

FORCEINLINE NTAPI VOID StorPortReadPortBufferUchar(IN PVOID HwDeviceExtension,
						   IN PUCHAR Port,
						   IN PUCHAR Buffer,
						   IN ULONG Count)
{
    READ_PORT_BUFFER_UCHAR(Port, Buffer, Count);
}

FORCEINLINE NTAPI VOID StorPortReadPortBufferUlong(IN PVOID HwDeviceExtension,
						   IN PULONG Port,
						   IN PULONG Buffer,
						   IN ULONG Count)
{
    READ_PORT_BUFFER_ULONG(Port, Buffer, Count);
}

FORCEINLINE NTAPI VOID StorPortReadPortBufferUshort(IN PVOID HwDeviceExtension,
						    IN PUSHORT Port,
						    IN PUSHORT Buffer,
						    IN ULONG Count)
{
    READ_PORT_BUFFER_USHORT(Port, Buffer, Count);
}

FORCEINLINE NTAPI UCHAR StorPortReadPortUchar(IN PVOID HwDeviceExtension,
					      IN PUCHAR Port)
{
    return READ_PORT_UCHAR(Port);
}

FORCEINLINE NTAPI ULONG StorPortReadPortUlong(IN PVOID HwDeviceExtension,
					      IN PULONG Port)
{
    return READ_PORT_ULONG(Port);
}

FORCEINLINE NTAPI USHORT StorPortReadPortUshort(IN PVOID HwDeviceExtension,
						IN PUSHORT Port)
{
    return READ_PORT_USHORT(Port);
}

FORCEINLINE NTAPI VOID StorPortReadRegisterBufferUchar(IN PVOID HwDeviceExtension,
						       IN PUCHAR Register,
						       IN PUCHAR Buffer,
						       IN ULONG Count)
{
    READ_REGISTER_BUFFER_UCHAR(Register, Buffer, Count);
}

FORCEINLINE NTAPI VOID StorPortReadRegisterBufferUlong(IN PVOID HwDeviceExtension,
						       IN PULONG Register,
						       IN PULONG Buffer,
						       IN ULONG Count)
{
    READ_REGISTER_BUFFER_ULONG(Register, Buffer, Count);
}

FORCEINLINE NTAPI VOID StorPortReadRegisterBufferUshort(IN PVOID HwDeviceExtension,
							IN PUSHORT Register,
							IN PUSHORT Buffer,
							IN ULONG Count)
{
    READ_REGISTER_BUFFER_USHORT(Register, Buffer, Count);
}

FORCEINLINE NTAPI UCHAR StorPortReadRegisterUchar(IN PVOID HwDeviceExtension,
						  IN PUCHAR Register)
{
    return READ_REGISTER_UCHAR(Register);
}

FORCEINLINE NTAPI ULONG StorPortReadRegisterUlong(IN PVOID HwDeviceExtension,
						  IN PULONG Register)
{
    return READ_REGISTER_ULONG(Register);
}

FORCEINLINE NTAPI USHORT StorPortReadRegisterUshort(IN PVOID HwDeviceExtension,
						    IN PUSHORT Register)
{
    return READ_REGISTER_USHORT(Register);
}

FORCEINLINE NTAPI VOID StorPortWritePortBufferUchar(IN PVOID HwDeviceExtension,
						    IN PUCHAR Port,
						    IN PUCHAR Buffer,
						    IN ULONG Count)
{
    WRITE_PORT_BUFFER_UCHAR(Port, Buffer, Count);
}

FORCEINLINE NTAPI VOID StorPortWritePortBufferUlong(IN PVOID HwDeviceExtension,
						    IN PULONG Port,
						    IN PULONG Buffer,
						    IN ULONG Count)
{
    WRITE_PORT_BUFFER_ULONG(Port, Buffer, Count);
}

FORCEINLINE NTAPI VOID StorPortWritePortBufferUshort(IN PVOID HwDeviceExtension,
						     IN PUSHORT Port,
						     IN PUSHORT Buffer,
						     IN ULONG Count)
{
    WRITE_PORT_BUFFER_USHORT(Port, Buffer, Count);
}

FORCEINLINE NTAPI VOID StorPortWritePortUchar(IN PVOID HwDeviceExtension,
					      IN PUCHAR Port,
					      IN UCHAR Value)
{
    WRITE_PORT_UCHAR(Port, Value);
}

FORCEINLINE NTAPI VOID StorPortWritePortUlong(IN PVOID HwDeviceExtension,
					      IN PULONG Port,
					      IN ULONG Value)
{
    WRITE_PORT_ULONG(Port, Value);
}

FORCEINLINE NTAPI VOID StorPortWritePortUshort(IN PVOID HwDeviceExtension,
					       IN PUSHORT Port,
					       IN USHORT Value)
{
    WRITE_PORT_USHORT(Port, Value);
}

FORCEINLINE NTAPI VOID StorPortWriteRegisterBufferUchar(IN PVOID HwDeviceExtension,
							IN PUCHAR Register,
							IN PUCHAR Buffer,
							IN ULONG Count)
{
    WRITE_REGISTER_BUFFER_UCHAR(Register, Buffer, Count);
}

FORCEINLINE NTAPI VOID StorPortWriteRegisterBufferUlong(IN PVOID HwDeviceExtension,
							IN PULONG Register,
							IN PULONG Buffer,
							IN ULONG Count)
{
    WRITE_REGISTER_BUFFER_ULONG(Register, Buffer, Count);
}

FORCEINLINE NTAPI VOID StorPortWriteRegisterBufferUshort(IN PVOID HwDeviceExtension,
							 IN PUSHORT Register,
							 IN PUSHORT Buffer,
							 IN ULONG Count)
{
    WRITE_REGISTER_BUFFER_USHORT(Register, Buffer, Count);
}

FORCEINLINE NTAPI VOID StorPortWriteRegisterUchar(IN PVOID HwDeviceExtension,
						  IN PUCHAR Register,
						  IN UCHAR Value)
{
    WRITE_REGISTER_UCHAR(Register, Value);
}

FORCEINLINE NTAPI VOID StorPortWriteRegisterUlong(IN PVOID HwDeviceExtension,
						  IN PULONG Register,
						  IN ULONG Value)
{
    WRITE_REGISTER_ULONG(Register, Value);
}

FORCEINLINE NTAPI VOID StorPortWriteRegisterUshort(IN PVOID HwDeviceExtension,
						   IN PUSHORT Register,
						   IN USHORT Value)
{
    WRITE_REGISTER_USHORT(Register, Value);
}

FORCEINLINE BOOLEAN StorPortEnablePassiveInitialization(IN PVOID DeviceExtension,
							IN PHW_PASSIVE_INITIALIZE_ROUTINE Routine)
{
    LONG Success = FALSE;
    StorPortNotification(EnablePassiveInitialization, DeviceExtension,
			 Routine, &Success);
    return (BOOLEAN)Success;
}

FORCEINLINE VOID StorPortInitializeDpc(IN PVOID DeviceExtension,
				       OUT PSTOR_DPC Dpc,
				       IN PHW_DPC_ROUTINE HwDpcRoutine)
{
    StorPortNotification(InitializeDpc, DeviceExtension, Dpc, HwDpcRoutine);
}

FORCEINLINE BOOLEAN StorPortIssueDpc(IN PVOID DeviceExtension,
				     IN PSTOR_DPC Dpc,
				     IN PVOID SystemArgument1,
				     IN PVOID SystemArgument2)
{
    LONG Success = FALSE;
    StorPortNotification(IssueDpc, DeviceExtension, Dpc,
			 SystemArgument1, SystemArgument2, &Success);
    return (BOOLEAN)Success;
}

FORCEINLINE VOID StorPortAcquireSpinLock(IN PVOID DeviceExtension,
					 IN STOR_SPINLOCK SpinLock,
					 IN PVOID LockContext,
					 IN OUT PSTOR_LOCK_HANDLE LockHandle)
{
    StorPortNotification(AcquireSpinLock, DeviceExtension, SpinLock,
			 LockContext, LockHandle);
}

FORCEINLINE VOID StorPortReleaseSpinLock(IN PVOID DeviceExtension,
					 IN OUT PSTOR_LOCK_HANDLE LockHandle)
{
    StorPortNotification(ReleaseSpinLock, DeviceExtension, LockHandle);
}

STORPORT_API ULONG StorPortExtendedFunction(IN STORPORT_FUNCTION_CODE FunctionCode,
					    IN PVOID HwDeviceExtension, ...);

FORCEINLINE ULONG StorPortAllocatePool(IN PVOID HwDeviceExtension,
				       IN ULONG NumberOfBytes,
				       IN ULONG Tag,
				       OUT PVOID *BufferPointer)
{
    return StorPortExtendedFunction(ExtFunctionAllocatePool,
				    HwDeviceExtension,
				    NumberOfBytes, Tag,
				    BufferPointer);
}

FORCEINLINE ULONG StorPortFreePool(IN PVOID HwDeviceExtension,
				   IN PVOID BufferPointer)
{
    return StorPortExtendedFunction(ExtFunctionFreePool,
				    HwDeviceExtension,
				    BufferPointer);
}

FORCEINLINE ULONG StorPortAllocateMdl(IN PVOID HwDeviceExtension,
				      IN PVOID BufferPointer,
				      IN ULONG NumberOfBytes,
				      OUT PVOID *Mdl)
{
    return StorPortExtendedFunction(ExtFunctionAllocateMdl,
				    HwDeviceExtension,
				    BufferPointer,
				    NumberOfBytes, Mdl);
}

FORCEINLINE ULONG StorPortFreeMdl(IN PVOID HwDeviceExtension,
				  IN PVOID Mdl)
{
    return StorPortExtendedFunction(ExtFunctionFreeMdl,
				    HwDeviceExtension, Mdl);
}

FORCEINLINE ULONG StorPortBuildMdlForNonPagedPool(IN PVOID HwDeviceExtension,
						  IN OUT PVOID Mdl)
{
    return StorPortExtendedFunction(ExtFunctionBuildMdlForNonPagedPool,
				    HwDeviceExtension, Mdl);
}

FORCEINLINE ULONG StorPortGetSystemAddress(IN PVOID HwDeviceExtension,
					   IN PSCSI_REQUEST_BLOCK Srb,
					   OUT PVOID *SystemAddress)
{
    return StorPortExtendedFunction(ExtFunctionGetSystemAddress,
				    HwDeviceExtension, Srb,
				    SystemAddress);
}

FORCEINLINE ULONG StorPortGetOriginalMdl(IN PVOID HwDeviceExtension,
					 IN PSCSI_REQUEST_BLOCK Srb,
					 OUT PVOID *Mdl)
{
    return StorPortExtendedFunction(ExtFunctionGetOriginalMdl,
				    HwDeviceExtension, Srb, Mdl);
}

FORCEINLINE ULONG StorPortCompleteServiceIrp(IN PVOID HwDeviceExtension,
					     IN PVOID Irp)
{
    return StorPortExtendedFunction(ExtFunctionCompleteServiceIrp,
				    HwDeviceExtension, Irp);
}

FORCEINLINE ULONG StorPortGetDeviceObjects(IN PVOID HwDeviceExtension,
					   OUT PVOID *AdapterDeviceObject,
					   OUT PVOID *PhysicalDeviceObject,
					   OUT PVOID *LowerDeviceObject)
{
    return StorPortExtendedFunction(ExtFunctionGetDeviceObjects, HwDeviceExtension,
				    AdapterDeviceObject, PhysicalDeviceObject,
				    LowerDeviceObject);
}

FORCEINLINE ULONG StorPortBuildScatterGatherList(IN PVOID HwDeviceExtension,
						 IN PVOID Mdl,
						 IN PVOID CurrentVa,
						 IN ULONG Length,
						 IN PpostScaterGatherExecute Routine,
						 IN PVOID Context,
						 IN BOOLEAN WriteToDevice,
						 IN OUT PVOID ScatterGatherBuffer,
						 IN ULONG ScatterGatherBufferLength)
{
    return StorPortExtendedFunction(ExtFunctionBuildScatterGatherList,
				    HwDeviceExtension, Mdl, CurrentVa,
				    Length, Routine, Context,
				    WriteToDevice, ScatterGatherBuffer,
				    ScatterGatherBufferLength);
}

FORCEINLINE ULONG StorPortPutScatterGatherList(IN PVOID HwDeviceExtension,
					       IN PSTOR_SCATTER_GATHER_LIST List,
					       IN BOOLEAN WriteToDevice)
{
    return StorPortExtendedFunction(ExtFunctionPutScatterGatherList,
				    HwDeviceExtension,
				    List, WriteToDevice);
}

FORCEINLINE ULONG StorPortAcquireMSISpinLock(IN PVOID HwDeviceExtension,
					     IN ULONG MessageId,
					     IN PULONG OldIrql)
{
    return StorPortExtendedFunction(ExtFunctionAcquireMSISpinLock,
				    HwDeviceExtension,
				    MessageId, OldIrql);
}

FORCEINLINE ULONG StorPortReleaseMSISpinLock(IN PVOID HwDeviceExtension,
					     IN ULONG MessageId,
					     IN ULONG OldIrql)
{
    return StorPortExtendedFunction(ExtFunctionReleaseMSISpinLock,
				    HwDeviceExtension,
				    MessageId, OldIrql);
}

FORCEINLINE ULONG StorPortGetMSIInfo(IN PVOID HwDeviceExtension,
				     IN ULONG MessageId,
				     OUT PMESSAGE_INTERRUPT_INFORMATION Info)
{
    return StorPortExtendedFunction(ExtFunctionGetMessageInterruptInformation,
				    HwDeviceExtension, MessageId, Info);
}

FORCEINLINE ULONG StorPortInitializePerfOpts(IN PVOID HwDeviceExtension,
					     IN BOOLEAN Query,
					     IN OUT PPERF_CONFIGURATION_DATA Data)
{
    return StorPortExtendedFunction(ExtFunctionInitializePerformanceOptimizations,
				    HwDeviceExtension, Query, Data);
}

FORCEINLINE ULONG StorPortGetStartIoPerfParams(IN PVOID HwDeviceExtension,
					       IN PSCSI_REQUEST_BLOCK Srb,
					       IN OUT PSTARTIO_PERFORMANCE_PARAMETERS Params)
{
    return StorPortExtendedFunction(ExtFunctionGetStartIoPerformanceParameters,
				    HwDeviceExtension, Srb, Params);
}

FORCEINLINE ULONG StorPortLogSystemEvent(IN PVOID HwDeviceExtension,
					 IN OUT PSTOR_LOG_EVENT_DETAILS LogDetails,
					 IN OUT PULONG MaximumSize)
{
    return StorPortExtendedFunction(ExtFunctionLogSystemEvent, HwDeviceExtension,
				    LogDetails, MaximumSize);
}

FORCEINLINE ULONG StorPortGetGroupAffinity(IN PVOID HwDeviceExtension,
					   IN USHORT GroupNumber,
					   OUT PKAFFINITY GroupAffinityMask)
{
    return StorPortExtendedFunction(ExtFunctionGetGroupAffinity,
                                    HwDeviceExtension,
                                    GroupNumber,
                                    GroupAffinityMask);
}

FORCEINLINE ULONG StorPortGetActiveGroupCount(IN PVOID HwDeviceExtension,
					      OUT PUSHORT NumberGroups)
{
    return StorPortExtendedFunction(ExtFunctionGetActiveGroupCount,
                                    HwDeviceExtension,
                                    NumberGroups);
}

FORCEINLINE ULONG StorPortGetNodeAffinity(IN PVOID HwDeviceExtension,
					  IN ULONG NodeNumber,
					  OUT PGROUP_AFFINITY NodeAffinityMask)
{
    return StorPortExtendedFunction(ExtFunctionGetNodeAffinity,
                                    HwDeviceExtension,
                                    NodeNumber,
                                    NodeAffinityMask);
}

FORCEINLINE ULONG StorPortGetActiveNodeCount(IN PVOID HwDeviceExtension,
					     OUT PULONG NumberNodes)
{
    return StorPortExtendedFunction(ExtFunctionGetActiveNodeCount,
                                    HwDeviceExtension,
                                    NumberNodes);
}

FORCEINLINE ULONG StorPortGetHighestNodeNumber(IN PVOID HwDeviceExtension,
					       OUT PULONG HighestNode)
{
    return StorPortExtendedFunction(ExtFunctionGetHighestNodeNumber,
                                    HwDeviceExtension,
                                    HighestNode);
}

FORCEINLINE ULONG StorPortAllocateContiguousMemorySpecifyCacheNode(IN PVOID HwDeviceExtension,
								   IN SIZE_T NumberOfBytes,
								   IN PHYSICAL_ADDRESS LowestAcceptableAddress,
								   IN PHYSICAL_ADDRESS HighestAcceptableAddress,
								   IN OPTIONAL PHYSICAL_ADDRESS BoundaryAddressMultiple,
								   IN MEMORY_CACHING_TYPE CacheType,
								   IN NODE_REQUIREMENT PreferredNode,
								   OUT PVOID* BufferPointer)
{
    return StorPortExtendedFunction(ExtFunctionAllocateContiguousMemorySpecifyCacheNode,
                                    HwDeviceExtension,
                                    NumberOfBytes,
                                    LowestAcceptableAddress,
                                    HighestAcceptableAddress,
                                    BoundaryAddressMultiple,
                                    CacheType,
                                    PreferredNode,
                                    BufferPointer);
}

FORCEINLINE ULONG StorPortFreeContiguousMemorySpecifyCache(IN PVOID HwDeviceExtension,
							   IN PVOID BaseAddress,
							   IN SIZE_T NumberOfBytes,
							   IN MEMORY_CACHING_TYPE CacheType)
{
    return StorPortExtendedFunction(ExtFunctionFreeContiguousMemorySpecifyCache,
                                    HwDeviceExtension,
                                    BaseAddress,
                                    NumberOfBytes,
                                    CacheType);
}


FORCEINLINE ULONG StorPortSetPowerSettingNotificationGuids(IN PVOID  HwDeviceExtension,
							   IN ULONG  GuidCount,
							   IN LPGUID Guid)
{
    return StorPortExtendedFunction(ExtFunctionSetPowerSettingNotificationGuids,
                                    HwDeviceExtension,
                                    GuidCount,
                                    Guid);
}

FORCEINLINE ULONG StorPortInvokeAcpiMethod(IN      PVOID HwDeviceExtension,
					   IN OPTIONAL  PSTOR_ADDRESS Address,
					   IN      ULONG MethodName,
					   IN OPTIONAL  PVOID InputBuffer,
					   IN      ULONG InputBufferLength,
					   OUT OPTIONAL PVOID OutputBuffer,
					   IN      ULONG OutputBufferLength,
					   OUT OPTIONAL PULONG BytesReturned)
{
    return StorPortExtendedFunction(ExtFunctionInvokeAcpiMethod,
                                    HwDeviceExtension,
                                    Address,
                                    MethodName,
                                    InputBuffer,
                                    InputBufferLength,
                                    OutputBuffer,
                                    OutputBufferLength,
                                    BytesReturned);
}

FORCEINLINE ULONG StorPortGetActivityIdSrb(IN PVOID HwDeviceExtension,
					   IN PSCSI_REQUEST_BLOCK Srb,
					   OUT LPGUID ActivityId)
{
    return StorPortExtendedFunction(ExtFunctionGetActivityId,
                                    HwDeviceExtension,
                                    Srb,
                                    ActivityId);
}

FORCEINLINE ULONG StorPortGetDataInBufferMdl(IN PVOID HwDeviceExtension,
					     IN PSCSI_REQUEST_BLOCK Srb,
					     OUT PVOID* Mdl)
{
    return StorPortExtendedFunction(ExtFunctionGetDataInBufferMdl,
                                    HwDeviceExtension,
                                    Srb,
                                    Mdl);
}

FORCEINLINE ULONG StorPortGetDataInBufferSystemAddress(IN PVOID HwDeviceExtension,
						       IN PSCSI_REQUEST_BLOCK Srb,
						       OUT PVOID* SystemAddress)
{
    return StorPortExtendedFunction(ExtFunctionGetDataInBufferSystemAddress,
                                    HwDeviceExtension,
                                    Srb,
                                    SystemAddress);
}

FORCEINLINE ULONG StorPortGetDataInBufferScatterGatherList(IN PVOID HwDeviceExtension,
							   IN PSCSI_REQUEST_BLOCK Srb,
							   OUT PSTOR_SCATTER_GATHER_LIST* SgList)
{
    return StorPortExtendedFunction(ExtFunctionGetDataInBufferScatterGatherList,
                                    HwDeviceExtension,
                                    Srb,
                                    SgList);
}


FORCEINLINE ULONG StorPortFlushDataBufferMdl(IN PVOID HwDeviceExtension,
					     IN PSCSI_REQUEST_BLOCK Srb)
{
#if defined (_ARM_)
    return StorPortExtendedFunction(ExtFunctionFlushDataBufferMdl,
                                    HwDeviceExtension,
                                    Srb);
#else
    UNREFERENCED_PARAMETER(HwDeviceExtension);
    UNREFERENCED_PARAMETER(Srb);

    return STOR_STATUS_SUCCESS;
#endif
}

FORCEINLINE ULONG StorPortRegistryReadAdapterKey(IN PVOID HwDeviceExtension,
						 IN OPTIONAL PUCHAR SubKeyName,
						 IN PUCHAR ValueName,
						 IN ULONG ValueType,
						 _Inout_ PVOID *ValueData,
						 _Inout_ PULONG ValueDataLength)
{
    return StorPortExtendedFunction(ExtFunctionRegistryReadAdapterKey,
                                    HwDeviceExtension,
                                    SubKeyName,
                                    ValueName,
                                    ValueType,
                                    ValueData,
                                    ValueDataLength);
}

FORCEINLINE ULONG StorPortRegistryWriteAdapterKey(IN PVOID HwDeviceExtension,
						  IN OPTIONAL PUCHAR SubKeyName,
						  IN PUCHAR ValueName,
						  IN ULONG ValueType,
						  IN PVOID ValueData,
						  IN ULONG ValueDataLength)
{
    return StorPortExtendedFunction(ExtFunctionRegistryWriteAdapterKey,
                                    HwDeviceExtension,
                                    SubKeyName,
                                    ValueName,
                                    ValueType,
                                    ValueData,
                                    ValueDataLength);
}

FORCEINLINE ULONG StorPortMarkDumpMemory(IN PVOID HwDeviceExtension,
					 IN PVOID Address,
					 IN ULONG_PTR Length,
					 IN ULONG Flags)
{
    return StorPortExtendedFunction(ExtFunctionMarkDumpMemory,
                                    HwDeviceExtension,
                                    Address,
                                    Length,
                                    Flags);
}

FORCEINLINE ULONG StorPortSetUnitAttributes(IN PVOID HwDeviceExtension,
					    IN PSTOR_ADDRESS Address,
					    IN STOR_UNIT_ATTRIBUTES Attributes)
{
    return StorPortExtendedFunction(ExtFunctionSetUnitAttributes,
                                    HwDeviceExtension,
                                    Address,
                                    Attributes);
}

FORCEINLINE ULONG StorPortQueryPerformanceCounter(IN PVOID HwDeviceExtension,
						  OUT OPTIONAL PLARGE_INTEGER Frequency,
						  OUT PLARGE_INTEGER PerformanceCounter)
{
    return StorPortExtendedFunction(ExtFunctionQueryPerformanceCounter,
                                    HwDeviceExtension,
                                    Frequency,
                                    PerformanceCounter);
}

FORCEINLINE ULONG StorPortGetRequestInfo(IN PVOID HwDeviceExtension,
					 IN PSCSI_REQUEST_BLOCK Srb,
					 OUT PSTOR_REQUEST_INFO RequestInfo)
{
    return StorPortExtendedFunction(ExtFunctionGetRequestInfo,
                                    HwDeviceExtension,
                                    Srb,
                                    RequestInfo);
}

FORCEINLINE ULONG StorPortInitializeWorker(IN PVOID HwDeviceExtension,
					   OUT PVOID *Worker)
{
    return StorPortExtendedFunction(ExtFunctionInitializeWorker,
                                    HwDeviceExtension,
                                    Worker);
}

FORCEINLINE ULONG StorPortQueueWorkItem(IN PVOID HwDeviceExtension,
					IN PHW_WORKITEM WorkItemCallback,
					IN PVOID Worker,
					IN OPTIONAL PVOID Context)
{
    return StorPortExtendedFunction(ExtFunctionQueueWorkItem,
                                    HwDeviceExtension,
                                    WorkItemCallback,
                                    Worker,
                                    Context);
}

FORCEINLINE ULONG StorPortFreeWorker(IN PVOID HwDeviceExtension,
				     IN PVOID Worker)
{
    return StorPortExtendedFunction(ExtFunctionFreeWorker,
                                    HwDeviceExtension,
                                    Worker);
}

FORCEINLINE ULONG StorPortInitializeTimer(IN PVOID HwDeviceExtension,
					  OUT PVOID *TimerHandle)
{
    return StorPortExtendedFunction(ExtFunctionInitializeTimer,
                                    HwDeviceExtension,
                                    TimerHandle);
}

FORCEINLINE ULONG StorPortRequestTimer(IN PVOID HwDeviceExtension,
				       IN PVOID TimerHandle,
				       IN PHW_TIMER_EX TimerCallback,
				       IN OPTIONAL PVOID CallbackContext,
				       IN ULONGLONG TimerValue,
				       IN ULONGLONG TolerableDelay)
{
    return StorPortExtendedFunction(ExtFunctionRequestTimer,
                                    HwDeviceExtension,
                                    TimerHandle,
                                    TimerCallback,
                                    CallbackContext,
                                    TimerValue,
                                    TolerableDelay);
}

FORCEINLINE ULONG StorPortFreeTimer(IN PVOID HwDeviceExtension,
				    IN PVOID TimerHandle)
{
    return StorPortExtendedFunction(ExtFunctionFreeTimer,
                                    HwDeviceExtension,
                                    TimerHandle);
}

FORCEINLINE ULONG StorPortStateChangeDetected(IN PVOID HwDeviceExtension,
					      IN ULONG ChangedEntity,
					      IN PSTOR_ADDRESS Address,
					      IN ULONG Attributes,
					      IN PHW_STATE_CHANGE HwStateChange,
					      IN OPTIONAL PVOID HwStateChangeContext)
{
    ULONG Status = STOR_STATUS_NOT_IMPLEMENTED;
    StorPortNotification(StateChangeDetectedCall,
			 HwDeviceExtension,
			 ChangedEntity,
			 Address,
			 Attributes,
			 HwStateChange,
			 HwStateChangeContext,
			 &Status);
    return Status;
}

FORCEINLINE ULONG StorPortAsyncNotificationDetected(IN PVOID HwDeviceExtension,
						    IN PSTOR_ADDRESS Address,
						    IN ULONGLONG Flags)
{
    ULONG Status = STOR_STATUS_NOT_IMPLEMENTED;
    StorPortNotification(AsyncNotificationDetected,
			 HwDeviceExtension,
			 Address,
			 Flags,
			 &Status);
    return Status;
}

FORCEINLINE ULONG StorPortInitializePoFxPower(IN PVOID HwDeviceExtension,
					      IN OPTIONAL PSTOR_ADDRESS Address,
					      IN PSTOR_POFX_DEVICE Device,
					      IN OUT PBOOLEAN D3ColdEnabled)
{
    return StorPortExtendedFunction(ExtFunctionInitializePoFxPower,
                                    HwDeviceExtension,
                                    Address,
                                    Device,
				    D3ColdEnabled);
}

FORCEINLINE ULONG StorPortPoFxActivateComponent(IN PVOID HwDeviceExtension,
						IN OPTIONAL PSTOR_ADDRESS Address,
						IN OPTIONAL PSCSI_REQUEST_BLOCK Srb,
						IN ULONG Component,
						IN ULONG Flags)
{
    return STOR_STATUS_NOT_IMPLEMENTED;
}

FORCEINLINE ULONG StorPortPoFxIdleComponent(IN PVOID HwDeviceExtension,
					    IN OPTIONAL PSTOR_ADDRESS Address,
					    IN OPTIONAL PSCSI_REQUEST_BLOCK Srb,
					    IN ULONG Component,
					    IN ULONG Flags)
{
    return STOR_STATUS_NOT_IMPLEMENTED;
}

static const GUID STORPORT_DEVICEOPERATION_SECURE_REPROVISION_GUID = {
    0xdcaf9c10, 0x895f, 0x481f, { 0xa4, 0x92, 0xd4, 0xce, 0xd2, 0xf5, 0x56, 0x33 }
};

static const GUID STORPORT_DEVICEOPERATION_USE_INLINE_CRYPTO_ENGINE_GUID = {
    0xd52ce820, 0x2b37, 0x444b, { 0xa6, 0x33, 0x00, 0x92, 0xe5, 0x91, 0xd0, 0x7b }
};

static const GUID STORPORT_DEVICEOPERATION_CACHED_SETTINGS_INIT_GUID = {
    0x2b9443ac, 0xf89b, 0x48e8, { 0xb2, 0x92, 0x2c, 0xb6, 0xc9, 0x6e, 0xfd, 0x5a }
};

FORCEINLINE ULONG StorPortIsDeviceOperationAllowed(IN PVOID HwDeviceExtension,
						   IN PSTOR_ADDRESS Address,
						   IN LPCGUID DeviceOperation,
						   OUT ULONG *AllowedFlag)
{
    return StorPortExtendedFunction(ExtFunctionDeviceOperationAllowed,
                                    HwDeviceExtension,
                                    Address,
                                    DeviceOperation,
                                    AllowedFlag);
}

FORCEINLINE ULONG StorPortGetD3ColdSupport(IN PVOID HwDeviceExtension,
					   IN OPTIONAL PVOID Address,
					   OUT PBOOLEAN Supported)
{
    return StorPortExtendedFunction(ExtFunctionGetD3ColdSupport,
                                    HwDeviceExtension,
                                    Address,
                                    Supported);
}

FORCEINLINE ULONG StorPortEtwEvent2(IN PVOID HwDeviceExtension,
				    IN OPTIONAL PSTOR_ADDRESS Address,
				    IN ULONG EventId,
				    IN PWSTR EventDescription,
				    IN ULONGLONG EventKeywords,
				    IN STORPORT_ETW_LEVEL EventLevel,
				    IN STORPORT_ETW_EVENT_OPCODE EventOpcode,
				    IN OPTIONAL PSCSI_REQUEST_BLOCK Srb,
				    IN PWSTR Parameter1Name,
				    IN ULONGLONG Parameter1Value,
				    IN PWSTR Parameter2Name,
				    IN ULONGLONG Parameter2Value)
{
    return StorPortExtendedFunction(ExtFunctionMiniportEtwEvent2,
				    HwDeviceExtension,
				    Address,
				    EventId,
				    EventDescription,
				    EventKeywords,
				    EventLevel,
				    EventOpcode,
				    Srb,
				    Parameter1Name,
				    Parameter1Value,
				    Parameter2Name,
				    Parameter2Value);
}

FORCEINLINE ULONG StorPortEtwEvent4(IN PVOID HwDeviceExtension,
				    IN OPTIONAL PSTOR_ADDRESS Address,
				    IN ULONG EventId,
				    IN PWSTR EventDescription,
				    IN ULONGLONG EventKeywords,
				    IN STORPORT_ETW_LEVEL EventLevel,
				    IN STORPORT_ETW_EVENT_OPCODE EventOpcode,
				    IN OPTIONAL PSCSI_REQUEST_BLOCK Srb,
				    IN PWSTR Parameter1Name,
				    IN ULONGLONG Parameter1Value,
				    IN PWSTR Parameter2Name,
				    IN ULONGLONG Parameter2Value,
				    IN PWSTR Parameter3Name,
				    IN ULONGLONG Parameter3Value,
				    IN PWSTR Parameter4Name,
				    IN ULONGLONG Parameter4Value)
{
    return StorPortExtendedFunction(ExtFunctionMiniportEtwEvent4,
				    HwDeviceExtension,
				    Address,
				    EventId,
				    EventDescription,
				    EventKeywords,
				    EventLevel,
				    EventOpcode,
				    Srb,
				    Parameter1Name,
				    Parameter1Value,
				    Parameter2Name,
				    Parameter2Value,
				    Parameter3Name,
				    Parameter3Value,
				    Parameter4Name,
				    Parameter4Value);
}

FORCEINLINE ULONG StorPortEtwEvent8(IN PVOID HwDeviceExtension,
				    IN OPTIONAL PSTOR_ADDRESS Address,
				    IN ULONG EventId,
				    IN PWSTR EventDescription,
				    IN ULONGLONG EventKeywords,
				    IN STORPORT_ETW_LEVEL EventLevel,
				    IN STORPORT_ETW_EVENT_OPCODE EventOpcode,
				    IN OPTIONAL PSCSI_REQUEST_BLOCK Srb,
				    IN PWSTR Parameter1Name,
				    IN ULONGLONG Parameter1Value,
				    IN PWSTR Parameter2Name,
				    IN ULONGLONG Parameter2Value,
				    IN PWSTR Parameter3Name,
				    IN ULONGLONG Parameter3Value,
				    IN PWSTR Parameter4Name,
				    IN ULONGLONG Parameter4Value,
				    IN PWSTR Parameter5Name,
				    IN ULONGLONG Parameter5Value,
				    IN PWSTR Parameter6Name,
				    IN ULONGLONG Parameter6Value,
				    IN PWSTR Parameter7Name,
				    IN ULONGLONG Parameter7Value,
				    IN PWSTR Parameter8Name,
				    IN ULONGLONG Parameter8Value
    )
{
    return StorPortExtendedFunction(ExtFunctionMiniportEtwEvent8,
                                    HwDeviceExtension,
                                    Address,
                                    EventId,
                                    EventDescription,
                                    EventKeywords,
                                    EventLevel,
                                    EventOpcode,
                                    Srb,
                                    Parameter1Name,
                                    Parameter1Value,
                                    Parameter2Name,
                                    Parameter2Value,
                                    Parameter3Name,
                                    Parameter3Value,
                                    Parameter4Name,
                                    Parameter4Value,
                                    Parameter5Name,
                                    Parameter5Value,
                                    Parameter6Name,
                                    Parameter6Value,
                                    Parameter7Name,
                                    Parameter7Value,
                                    Parameter8Name,
                                    Parameter8Value);
}

FORCEINLINE ULONG StorPortEtwChannelEvent2(IN PVOID HwDeviceExtension,
					   IN OPTIONAL PSTOR_ADDRESS Address,
					   IN STORPORT_ETW_EVENT_CHANNEL EventChannel,
					   IN ULONG EventId,
					   IN PWSTR EventDescription,
					   IN ULONGLONG EventKeywords,
					   IN STORPORT_ETW_LEVEL EventLevel,
					   IN STORPORT_ETW_EVENT_OPCODE EventOpcode,
					   IN PSCSI_REQUEST_BLOCK Srb,
					   IN PWSTR Parameter1Name,
					   IN ULONGLONG Parameter1Value,
					   IN PWSTR Parameter2Name,
					   IN ULONGLONG Parameter2Value)
{
    return STOR_STATUS_NOT_IMPLEMENTED;
}

FORCEINLINE ULONG StorPortEtwChannelEvent8(IN PVOID HwDeviceExtension,
					   IN OPTIONAL PSTOR_ADDRESS Address,
					   IN STORPORT_ETW_EVENT_CHANNEL EventChannel,
					   IN ULONG EventId,
					   IN PWSTR EventDescription,
					   IN ULONGLONG EventKeywords,
					   IN STORPORT_ETW_LEVEL EventLevel,
					   IN STORPORT_ETW_EVENT_OPCODE EventOpcode,
					   IN PSCSI_REQUEST_BLOCK Srb,
					   IN PWSTR Parameter1Name,
					   IN ULONGLONG Parameter1Value,
					   IN PWSTR Parameter2Name,
					   IN ULONGLONG Parameter2Value,
					   IN PWSTR Parameter3Name,
					   IN ULONGLONG Parameter3Value,
					   IN PWSTR Parameter4Name,
					   IN ULONGLONG Parameter4Value,
					   IN PWSTR Parameter5Name,
					   IN ULONGLONG Parameter5Value,
					   IN PWSTR Parameter6Name,
					   IN ULONGLONG Parameter6Value,
					   IN PWSTR Parameter7Name,
					   IN ULONGLONG Parameter7Value,
					   IN PWSTR Parameter8Name,
					   IN ULONGLONG Parameter8Value)
{
    return STOR_STATUS_NOT_IMPLEMENTED;
}

FORCEINLINE VOID StorPortMarkDeviceFailed(IN PVOID HwDeviceExtension,
					  IN OPTIONAL PSTOR_ADDRESS StorAddress,
					  IN ULONG Flags,
					  IN PWSTR FailReason) {}


#if DBG
#define DebugPrint(x) StorPortDebugPrint x
#else
#define DebugPrint(x)
#endif

#endif /* _NTSTORPORT_ */
