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

typedef PHYSICAL_ADDRESS STOR_PHYSICAL_ADDRESS, *PSTOR_PHYSICAL_ADDRESS;

typedef struct _ACCESS_RANGE {
    STOR_PHYSICAL_ADDRESS RangeStart;
    ULONG RangeLength;
    BOOLEAN RangeInMemory;
} ACCESS_RANGE, *PACCESS_RANGE;

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
    PVOID Reserved;
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
} PORT_CONFIGURATION_INFORMATION, *PPORT_CONFIGURATION_INFORMATION;

#define CONFIG_INFO_VERSION_2 sizeof(PORT_CONFIGURATION_INFORMATION)

#define STOR_MAP_NO_BUFFERS (0)
#define STOR_MAP_ALL_BUFFERS (1)
#define STOR_MAP_NON_READ_WRITE_BUFFERS (2)

typedef enum _STOR_SYNCHRONIZATION_MODEL {
    StorSynchronizeHalfDuplex,
    StorSynchronizeFullDuplex
} STOR_SYNCHRONIZATION_MODEL;

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
#if (NTDDI_VERSION >= NTDDI_WIN7)
    ExtFunctionGetCurrentProcessorNumber,
    ExtFunctionGetActiveGroupCount,
    ExtFunctionGetGroupAffinity,
    ExtFunctionGetActiveNodeCount,
    ExtFunctionGetNodeAffinity,
    ExtFunctionGetHighestNodeNumber,
    ExtFunctionGetLogicalProcessorRelationship,
    ExtFunctionAllocateContiguousMemorySpecifyCacheNode,
    ExtFunctionFreeContiguousMemorySpecifyCache
#endif
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

typedef PHYSICAL_ADDRESS STOR_PHYSICAL_ADDRESS;

typedef struct _MEMORY_REGION {
    PUCHAR VirtualBase;
    PHYSICAL_ADDRESS PhysicalBase;
    ULONG Length;
} MEMORY_REGION, *PMEMORY_REGION;

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
    ULONG_PTR Lock;
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

typedef BOOLEAN (NTAPI HW_INITIALIZE)(_In_ PVOID DeviceExtension);
typedef HW_INITIALIZE *PHW_INITIALIZE;

typedef BOOLEAN (NTAPI HW_BUILDIO)(_In_ PVOID DeviceExtension,
				   _In_ PSCSI_REQUEST_BLOCK Srb);
typedef HW_BUILDIO *PHW_BUILDIO;

typedef BOOLEAN (NTAPI HW_STARTIO)(_In_ PVOID DeviceExtension,
				   _In_ PSCSI_REQUEST_BLOCK Srb);
typedef HW_STARTIO *PHW_STARTIO;

typedef BOOLEAN (NTAPI HW_INTERRUPT)(_In_ PVOID DeviceExtension);
typedef HW_INTERRUPT *PHW_INTERRUPT;

typedef VOID (NTAPI HW_TIMER)(_In_ PVOID DeviceExtension);
typedef HW_TIMER *PHW_TIMER;

typedef VOID (NTAPI HW_DMA_STARTED)(_In_ PVOID DeviceExtension);
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

typedef SCSI_ADAPTER_CONTROL_STATUS (NTAPI HW_ADAPTER_CONTROL)(
    IN PVOID DeviceExtension, IN SCSI_ADAPTER_CONTROL_TYPE ControlType,
    IN PVOID Parameters);
typedef HW_ADAPTER_CONTROL *PHW_ADAPTER_CONTROL;

typedef BOOLEAN (HW_PASSIVE_INITIALIZE_ROUTINE)(_In_ PVOID DeviceExtension);
typedef HW_PASSIVE_INITIALIZE_ROUTINE *PHW_PASSIVE_INITIALIZE_ROUTINE;

typedef VOID (HW_DPC_ROUTINE)(_In_ PSTOR_DPC Dpc, _In_ PVOID HwDeviceExtension,
			      _In_ PVOID SystemArgument1, _In_ PVOID SystemArgument2);
typedef HW_DPC_ROUTINE *PHW_DPC_ROUTINE;

typedef BOOLEAN (NTAPI STOR_SYNCHRONIZED_ACCESS)(_In_ PVOID HwDeviceExtension,
						 _In_ PVOID Context);
typedef STOR_SYNCHRONIZED_ACCESS *PSTOR_SYNCHRONIZED_ACCESS;

typedef VOID (NTAPI *PpostScaterGatherExecute)(_In_ PVOID *DeviceObject, _In_ PVOID *Irp,
					       _In_ PSTOR_SCATTER_GATHER_LIST ScatterGather,
					       _In_ PVOID Context);

typedef BOOLEAN (NTAPI *PStorPortGetMessageInterruptInformation)(
    _In_ PVOID HwDeviceExtension, _In_ ULONG MessageId,
    _Out_ PMESSAGE_INTERRUPT_INFORMATION InterruptInfo);

typedef VOID (NTAPI *PStorPortPutScatterGatherList)(
    _In_ PVOID HwDeviceExtension, _In_ PSTOR_SCATTER_GATHER_LIST ScatterGatherList,
    _In_ BOOLEAN WriteToDevice);

typedef GETSGSTATUS (NTAPI *PStorPortBuildScatterGatherList)(
    _In_ PVOID HwDeviceExtension, _In_ PVOID Mdl, _In_ PVOID CurrentVa, _In_ ULONG Length,
    _In_ PpostScaterGatherExecute ExecutionRoutine, _In_ PVOID Context,
    _In_ BOOLEAN WriteToDevice, _Inout_ PVOID ScatterGatherBuffer,
    _In_ ULONG ScatterGatherBufferLength);

typedef VOID (NTAPI *PStorPortFreePool)(_In_ PVOID PMemory, _In_ PVOID HwDeviceExtension,
					_In_opt_ PVOID PMdl);

typedef PVOID (NTAPI *PStorPortAllocatePool)(_In_ ULONG NumberOfBytes, _In_ ULONG Tag,
					     _In_ PVOID HwDeviceExtension,
					     _Out_ PVOID *PMdl);

typedef PVOID (NTAPI *PStorPortGetSystemAddress)(_In_ PSCSI_REQUEST_BLOCK Srb);

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
} HW_INITIALIZATION_DATA, *PHW_INITIALIZATION_DATA;

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
    ReleaseSpinLock
} SCSI_NOTIFICATION_TYPE, *PSCSI_NOTIFICATION_TYPE;

#define StorPortCopyMemory(Destination, Source, Length) \
    memcpy((Destination), (Source), (Length))

#ifdef _STORPORT_
#define STORPORT_API
#else
#define STORPORT_API DECLSPEC_IMPORT
#endif

STORPORT_API
PUCHAR
NTAPI
StorPortAllocateRegistryBuffer(_In_ PVOID HwDeviceExtension, _In_ PULONG Length);

STORPORT_API
BOOLEAN
NTAPI
StorPortBusy(_In_ PVOID HwDeviceExtension, _In_ ULONG RequestsToComplete);

STORPORT_API
VOID NTAPI StorPortCompleteRequest(_In_ PVOID HwDeviceExtension, _In_ UCHAR PathId,
				   _In_ UCHAR TargetId, _In_ UCHAR Lun,
				   _In_ UCHAR SrbStatus);

STORPORT_API
ULONG64
NTAPI
StorPortConvertPhysicalAddressToUlong64(_In_ STOR_PHYSICAL_ADDRESS Address);

STORPORT_API
STOR_PHYSICAL_ADDRESS
NTAPI
StorPortConvertUlong64ToPhysicalAddress(_In_ ULONG64 UlongAddress);

STORPORT_API
VOID __cdecl StorPortDebugPrint(_In_ ULONG DebugPrintLevel, _In_ PCCHAR DebugMessage,
				...);

STORPORT_API
BOOLEAN
NTAPI
StorPortDeviceBusy(_In_ PVOID HwDeviceExtension, _In_ UCHAR PathId, _In_ UCHAR TargetId,
		   _In_ UCHAR Lun, _In_ ULONG RequestsToComplete);

STORPORT_API
BOOLEAN
NTAPI
StorPortDeviceReady(_In_ PVOID HwDeviceExtension, _In_ UCHAR PathId, _In_ UCHAR TargetId,
		    _In_ UCHAR Lun);

STORPORT_API
VOID NTAPI StorPortFreeDeviceBase(_In_ PVOID HwDeviceExtension, _In_ PVOID MappedAddress);

STORPORT_API
VOID NTAPI StorPortFreeRegistryBuffer(_In_ PVOID HwDeviceExtension, _In_ PUCHAR Buffer);

STORPORT_API
ULONG
NTAPI
StorPortGetBusData(_In_ PVOID DeviceExtension, _In_ ULONG BusDataType,
		   _In_ ULONG SystemIoBusNumber, _In_ ULONG SlotNumber,
		   _Out_ _When_(Length != 0, _Out_writes_bytes_(Length)) PVOID Buffer,
		   _In_ ULONG Length);

STORPORT_API
PVOID
NTAPI
StorPortGetDeviceBase(_In_ PVOID HwDeviceExtension, _In_ INTERFACE_TYPE BusType,
		      _In_ ULONG SystemIoBusNumber, _In_ STOR_PHYSICAL_ADDRESS IoAddress,
		      _In_ ULONG NumberOfBytes, _In_ BOOLEAN InIoSpace);

STORPORT_API
PVOID
NTAPI
StorPortGetLogicalUnit(_In_ PVOID HwDeviceExtension, _In_ UCHAR PathId,
		       _In_ UCHAR TargetId, _In_ UCHAR Lun);

STORPORT_API
STOR_PHYSICAL_ADDRESS
NTAPI
StorPortGetPhysicalAddress(_In_ PVOID HwDeviceExtension, _In_opt_ PSCSI_REQUEST_BLOCK Srb,
			   _In_ PVOID VirtualAddress, _Out_ ULONG *Length);

STORPORT_API
PSTOR_SCATTER_GATHER_LIST
NTAPI
StorPortGetScatterGatherList(_In_ PVOID DeviceExtension, _In_ PSCSI_REQUEST_BLOCK Srb);

STORPORT_API
PSCSI_REQUEST_BLOCK
NTAPI
StorPortGetSrb(_In_ PVOID DeviceExtension, _In_ UCHAR PathId, _In_ UCHAR TargetId,
	       _In_ UCHAR Lun, _In_ LONG QueueTag);

STORPORT_API
PVOID
NTAPI
StorPortGetUncachedExtension(_In_ PVOID HwDeviceExtension,
			     _In_ PPORT_CONFIGURATION_INFORMATION ConfigInfo,
			     _In_ ULONG NumberOfBytes);

STORPORT_API
PVOID
NTAPI
StorPortGetVirtualAddress(_In_ PVOID HwDeviceExtension,
			  _In_ STOR_PHYSICAL_ADDRESS PhysicalAddress);

STORPORT_API
ULONG
NTAPI
StorPortInitialize(_In_ PVOID Argument1, _In_ PVOID Argument2,
		   _In_ PHW_INITIALIZATION_DATA HwInitializationData,
		   _In_opt_ PVOID Unused);

STORPORT_API
VOID NTAPI StorPortLogError(_In_ PVOID HwDeviceExtension,
			    _In_opt_ PSCSI_REQUEST_BLOCK Srb, _In_ UCHAR PathId,
			    _In_ UCHAR TargetId, _In_ UCHAR Lun, _In_ ULONG ErrorCode,
			    _In_ ULONG UniqueId);

STORPORT_API
VOID NTAPI StorPortMoveMemory(_Out_writes_bytes_(Length) PVOID WriteBuffer,
			      _In_reads_bytes_(Length) PVOID ReadBuffer,
			      _In_ ULONG Length);

STORPORT_API
VOID __cdecl StorPortNotification(_In_ SCSI_NOTIFICATION_TYPE NotificationType,
				  _In_ PVOID HwDeviceExtension, ...);

STORPORT_API
VOID NTAPI StorPortQuerySystemTime(_Out_ PLARGE_INTEGER CurrentTime);

STORPORT_API
BOOLEAN
NTAPI
StorPortPause(_In_ PVOID HwDeviceExtension, _In_ ULONG TimeOut);

STORPORT_API
BOOLEAN
NTAPI
StorPortPauseDevice(_In_ PVOID HwDeviceExtension, _In_ UCHAR PathId, _In_ UCHAR TargetId,
		    _In_ UCHAR Lun, _In_ ULONG TimeOut);

STORPORT_API
VOID NTAPI StorPortReadPortBufferUchar(_In_ PVOID HwDeviceExtension, _In_ PUCHAR Port,
				       _In_ PUCHAR Buffer, _In_ ULONG Count);

STORPORT_API
VOID NTAPI StorPortReadPortBufferUlong(_In_ PVOID HwDeviceExtension, _In_ PULONG Port,
				       _In_ PULONG Buffer, _In_ ULONG Count);

STORPORT_API
VOID NTAPI StorPortReadPortBufferUshort(_In_ PVOID HwDeviceExtension, _In_ PUSHORT Port,
					_In_ PUSHORT Buffer, _In_ ULONG Count);

STORPORT_API
UCHAR
NTAPI
StorPortReadPortUchar(_In_ PVOID HwDeviceExtension, _In_ PUCHAR Port);

STORPORT_API
ULONG
NTAPI
StorPortReadPortUlong(_In_ PVOID HwDeviceExtension, _In_ PULONG Port);

STORPORT_API
USHORT
NTAPI
StorPortReadPortUshort(_In_ PVOID HwDeviceExtension, _In_ PUSHORT Port);

STORPORT_API
VOID NTAPI StorPortReadRegisterBufferUchar(_In_ PVOID HwDeviceExtension,
					   _In_ PUCHAR Register, _In_ PUCHAR Buffer,
					   _In_ ULONG Count);

STORPORT_API
VOID NTAPI StorPortReadRegisterBufferUlong(_In_ PVOID HwDeviceExtension,
					   _In_ PULONG Register, _In_ PULONG Buffer,
					   _In_ ULONG Count);

STORPORT_API
VOID NTAPI StorPortReadRegisterBufferUshort(_In_ PVOID HwDeviceExtension,
					    _In_ PUSHORT Register, _In_ PUSHORT Buffer,
					    _In_ ULONG Count);

STORPORT_API
UCHAR
NTAPI
StorPortReadRegisterUchar(_In_ PVOID HwDeviceExtension, _In_ PUCHAR Register);

STORPORT_API
ULONG
NTAPI
StorPortReadRegisterUlong(_In_ PVOID HwDeviceExtension, _In_ PULONG Register);

STORPORT_API
USHORT
NTAPI
StorPortReadRegisterUshort(_In_ PVOID HwDeviceExtension, _In_ PUSHORT Register);

STORPORT_API
BOOLEAN
NTAPI
StorPortReady(_In_ PVOID HwDeviceExtension);

STORPORT_API
BOOLEAN
NTAPI
StorPortRegistryRead(_In_ PVOID HwDeviceExtension, _In_ PUCHAR ValueName,
		     _In_ ULONG Global, _In_ ULONG Type, _In_ PUCHAR Buffer,
		     _In_ PULONG BufferLength);

STORPORT_API
BOOLEAN
NTAPI
StorPortRegistryWrite(_In_ PVOID HwDeviceExtension, _In_ PUCHAR ValueName,
		      _In_ ULONG Global, _In_ ULONG Type, _In_ PUCHAR Buffer,
		      _In_ ULONG BufferLength);

STORPORT_API
BOOLEAN
NTAPI
StorPortResume(_In_ PVOID HwDeviceExtension);

STORPORT_API
BOOLEAN
NTAPI
StorPortResumeDevice(_In_ PVOID HwDeviceExtension, _In_ UCHAR PathId, _In_ UCHAR TargetId,
		     _In_ UCHAR Lun);

STORPORT_API
ULONG
NTAPI
StorPortSetBusDataByOffset(_In_ PVOID DeviceExtension, _In_ ULONG BusDataType,
			   _In_ ULONG SystemIoBusNumber, _In_ ULONG SlotNumber,
			   _In_reads_bytes_(Length) PVOID Buffer, _In_ ULONG Offset,
			   _In_ ULONG Length);

STORPORT_API
BOOLEAN
NTAPI
StorPortSetDeviceQueueDepth(_In_ PVOID HwDeviceExtension, _In_ UCHAR PathId,
			    _In_ UCHAR TargetId, _In_ UCHAR Lun, _In_ ULONG Depth);

STORPORT_API
VOID NTAPI StorPortStallExecution(_In_ ULONG Delay);

STORPORT_API
VOID NTAPI StorPortSynchronizeAccess(
    _In_ PVOID HwDeviceExtension,
    _In_ PSTOR_SYNCHRONIZED_ACCESS SynchronizedAccessRoutine, _In_opt_ PVOID Context);

STORPORT_API
BOOLEAN
NTAPI
StorPortValidateRange(_In_ PVOID HwDeviceExtension, _In_ INTERFACE_TYPE BusType,
		      _In_ ULONG SystemIoBusNumber, _In_ STOR_PHYSICAL_ADDRESS IoAddress,
		      _In_ ULONG NumberOfBytes, _In_ BOOLEAN InIoSpace);

STORPORT_API
VOID NTAPI StorPortWritePortBufferUchar(_In_ PVOID HwDeviceExtension, _In_ PUCHAR Port,
					_In_ PUCHAR Buffer, _In_ ULONG Count);

STORPORT_API
VOID NTAPI StorPortWritePortBufferUlong(_In_ PVOID HwDeviceExtension, _In_ PULONG Port,
					_In_ PULONG Buffer, _In_ ULONG Count);

STORPORT_API
VOID NTAPI StorPortWritePortBufferUshort(_In_ PVOID HwDeviceExtension, _In_ PUSHORT Port,
					 _In_ PUSHORT Buffer, _In_ ULONG Count);

STORPORT_API
VOID NTAPI StorPortWritePortUchar(_In_ PVOID HwDeviceExtension, _In_ PUCHAR Port,
				  _In_ UCHAR Value);

STORPORT_API
VOID NTAPI StorPortWritePortUlong(_In_ PVOID HwDeviceExtension, _In_ PULONG Port,
				  _In_ ULONG Value);

STORPORT_API
VOID NTAPI StorPortWritePortUshort(_In_ PVOID HwDeviceExtension, _In_ PUSHORT Port,
				   _In_ USHORT Value);

STORPORT_API
VOID NTAPI StorPortWriteRegisterBufferUchar(_In_ PVOID HwDeviceExtension,
					    _In_ PUCHAR Register, _In_ PUCHAR Buffer,
					    _In_ ULONG Count);

STORPORT_API
VOID NTAPI StorPortWriteRegisterBufferUlong(_In_ PVOID HwDeviceExtension,
					    _In_ PULONG Register, _In_ PULONG Buffer,
					    _In_ ULONG Count);

STORPORT_API
VOID NTAPI StorPortWriteRegisterBufferUshort(_In_ PVOID HwDeviceExtension,
					     _In_ PUSHORT Register, _In_ PUSHORT Buffer,
					     _In_ ULONG Count);

STORPORT_API
VOID NTAPI StorPortWriteRegisterUchar(_In_ PVOID HwDeviceExtension, _In_ PUCHAR Register,
				      _In_ UCHAR Value);

STORPORT_API
VOID NTAPI StorPortWriteRegisterUlong(_In_ PVOID HwDeviceExtension, _In_ PULONG Register,
				      _In_ ULONG Value);

STORPORT_API
VOID NTAPI StorPortWriteRegisterUshort(_In_ PVOID HwDeviceExtension,
				       _In_ PUSHORT Register, _In_ USHORT Value);

FORCEINLINE
BOOLEAN
StorPortEnablePassiveInitialization(_In_ PVOID DeviceExtension,
				    _In_ PHW_PASSIVE_INITIALIZE_ROUTINE
					HwPassiveInitializeRoutine)
{
    LONG Succ;
    Succ = FALSE;
    StorPortNotification(EnablePassiveInitialization, DeviceExtension,
			 HwPassiveInitializeRoutine, &Succ);
    return (BOOLEAN)Succ;
}

FORCEINLINE
VOID StorPortInitializeDpc(_In_ PVOID DeviceExtension, _Out_ PSTOR_DPC Dpc,
			   _In_ PHW_DPC_ROUTINE HwDpcRoutine)
{
    StorPortNotification(InitializeDpc, DeviceExtension, Dpc, HwDpcRoutine);
}

FORCEINLINE
BOOLEAN
StorPortIssueDpc(_In_ PVOID DeviceExtension, _In_ PSTOR_DPC Dpc,
		 _In_ PVOID SystemArgument1, _In_ PVOID SystemArgument2)
{
    LONG Succ;
    Succ = FALSE;
    StorPortNotification(IssueDpc, DeviceExtension, Dpc, SystemArgument1, SystemArgument2,
			 &Succ);
    return (BOOLEAN)Succ;
}

FORCEINLINE
VOID StorPortAcquireSpinLock(_In_ PVOID DeviceExtension, _In_ STOR_SPINLOCK SpinLock,
			     _In_ PVOID LockContext, _Inout_ PSTOR_LOCK_HANDLE LockHandle)
{
    StorPortNotification(AcquireSpinLock, DeviceExtension, SpinLock, LockContext,
			 LockHandle);
}

FORCEINLINE
VOID StorPortReleaseSpinLock(_In_ PVOID DeviceExtension,
			     _Inout_ PSTOR_LOCK_HANDLE LockHandle)
{
    StorPortNotification(ReleaseSpinLock, DeviceExtension, LockHandle);
}

STORPORT_API
ULONG
StorPortExtendedFunction(_In_ STORPORT_FUNCTION_CODE FunctionCode,
			 _In_ PVOID HwDeviceExtension, ...);

FORCEINLINE
ULONG
StorPortAllocatePool(_In_ PVOID HwDeviceExtension, _In_ ULONG NumberOfBytes,
		     _In_ ULONG Tag, _Out_ PVOID *BufferPointer)
{
    return StorPortExtendedFunction(ExtFunctionAllocatePool, HwDeviceExtension,
				    NumberOfBytes, Tag, BufferPointer);
}

FORCEINLINE
ULONG
StorPortFreePool(_In_ PVOID HwDeviceExtension, _In_ PVOID BufferPointer)
{
    return StorPortExtendedFunction(ExtFunctionFreePool, HwDeviceExtension,
				    BufferPointer);
}

FORCEINLINE
ULONG
StorPortAllocateMdl(_In_ PVOID HwDeviceExtension, _In_ PVOID BufferPointer,
		    _In_ ULONG NumberOfBytes, _Out_ PVOID *Mdl)
{
    return StorPortExtendedFunction(ExtFunctionAllocateMdl, HwDeviceExtension,
				    BufferPointer, NumberOfBytes, Mdl);
}

FORCEINLINE
ULONG
StorPortFreeMdl(_In_ PVOID HwDeviceExtension, _In_ PVOID Mdl)
{
    return StorPortExtendedFunction(ExtFunctionFreeMdl, HwDeviceExtension, Mdl);
}

FORCEINLINE
ULONG
StorPortBuildMdlForNonPagedPool(_In_ PVOID HwDeviceExtension, _Inout_ PVOID Mdl)
{
    return StorPortExtendedFunction(ExtFunctionBuildMdlForNonPagedPool, HwDeviceExtension,
				    Mdl);
}

FORCEINLINE
ULONG
StorPortGetSystemAddress(_In_ PVOID HwDeviceExtension, _In_ PSCSI_REQUEST_BLOCK Srb,
			 _Out_ PVOID *SystemAddress)
{
    return StorPortExtendedFunction(ExtFunctionGetSystemAddress, HwDeviceExtension, Srb,
				    SystemAddress);
}

FORCEINLINE
ULONG
StorPortGetOriginalMdl(_In_ PVOID HwDeviceExtension, _In_ PSCSI_REQUEST_BLOCK Srb,
		       _Out_ PVOID *Mdl)
{
    return StorPortExtendedFunction(ExtFunctionGetOriginalMdl, HwDeviceExtension, Srb,
				    Mdl);
}

FORCEINLINE
ULONG
StorPortCompleteServiceIrp(_In_ PVOID HwDeviceExtension, _In_ PVOID Irp)
{
    return StorPortExtendedFunction(ExtFunctionCompleteServiceIrp, HwDeviceExtension,
				    Irp);
}

FORCEINLINE
ULONG
StorPortGetDeviceObjects(_In_ PVOID HwDeviceExtension, _Out_ PVOID *AdapterDeviceObject,
			 _Out_ PVOID *PhysicalDeviceObject,
			 _Out_ PVOID *LowerDeviceObject)
{
    return StorPortExtendedFunction(ExtFunctionGetDeviceObjects, HwDeviceExtension,
				    AdapterDeviceObject, PhysicalDeviceObject,
				    LowerDeviceObject);
}

FORCEINLINE
ULONG
StorPortBuildScatterGatherList(_In_ PVOID HwDeviceExtension, _In_ PVOID Mdl,
			       _In_ PVOID CurrentVa, _In_ ULONG Length,
			       _In_ PpostScaterGatherExecute ExecutionRoutine,
			       _In_ PVOID Context, _In_ BOOLEAN WriteToDevice,
			       _Inout_ PVOID ScatterGatherBuffer,
			       _In_ ULONG ScatterGatherBufferLength)
{
    return StorPortExtendedFunction(ExtFunctionBuildScatterGatherList, HwDeviceExtension,
				    Mdl, CurrentVa, Length, ExecutionRoutine, Context,
				    WriteToDevice, ScatterGatherBuffer,
				    ScatterGatherBufferLength);
}

FORCEINLINE
ULONG
StorPortPutScatterGatherList(_In_ PVOID HwDeviceExtension,
			     _In_ PSTOR_SCATTER_GATHER_LIST ScatterGatherList,
			     _In_ BOOLEAN WriteToDevice)
{
    return StorPortExtendedFunction(ExtFunctionPutScatterGatherList, HwDeviceExtension,
				    ScatterGatherList, WriteToDevice);
}

FORCEINLINE
ULONG
StorPortAcquireMSISpinLock(_In_ PVOID HwDeviceExtension, _In_ ULONG MessageId,
			   _In_ PULONG OldIrql)
{
    return StorPortExtendedFunction(ExtFunctionAcquireMSISpinLock, HwDeviceExtension,
				    MessageId, OldIrql);
}

FORCEINLINE
ULONG
StorPortReleaseMSISpinLock(_In_ PVOID HwDeviceExtension, _In_ ULONG MessageId,
			   _In_ ULONG OldIrql)
{
    return StorPortExtendedFunction(ExtFunctionReleaseMSISpinLock, HwDeviceExtension,
				    MessageId, OldIrql);
}

FORCEINLINE
ULONG
StorPortGetMSIInfo(_In_ PVOID HwDeviceExtension, _In_ ULONG MessageId,
		   _Out_ PMESSAGE_INTERRUPT_INFORMATION InterruptInfo)
{
    return StorPortExtendedFunction(ExtFunctionGetMessageInterruptInformation,
				    HwDeviceExtension, MessageId, InterruptInfo);
}

FORCEINLINE
ULONG
StorPortInitializePerfOpts(_In_ PVOID HwDeviceExtension, _In_ BOOLEAN Query,
			   _Inout_ PPERF_CONFIGURATION_DATA PerfConfigData)
{
    return StorPortExtendedFunction(ExtFunctionInitializePerformanceOptimizations,
				    HwDeviceExtension, Query, PerfConfigData);
}

FORCEINLINE
ULONG
StorPortGetStartIoPerfParams(_In_ PVOID HwDeviceExtension, _In_ PSCSI_REQUEST_BLOCK Srb,
			     _Inout_ PSTARTIO_PERFORMANCE_PARAMETERS StartIoPerfParams)
{
    return StorPortExtendedFunction(ExtFunctionGetStartIoPerformanceParameters,
				    HwDeviceExtension, Srb, StartIoPerfParams);
}

FORCEINLINE
ULONG
StorPortLogSystemEvent(_In_ PVOID HwDeviceExtension,
		       _Inout_ PSTOR_LOG_EVENT_DETAILS LogDetails,
		       _Inout_ PULONG MaximumSize)
{
    return StorPortExtendedFunction(ExtFunctionLogSystemEvent, HwDeviceExtension,
				    LogDetails, MaximumSize);
}

#if DBG
#define DebugPrint(x) StorPortDebugPrint x
#else
#define DebugPrint(x)
#endif

#endif /* _NTSTORPORT_ */
