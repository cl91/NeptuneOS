/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/pci.h
 * PURPOSE:         Main Header File
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

#ifndef _PCIDRV_H_
#define _PCIDRV_H_

#include <ntddk.h>
#include <hal.h>
#include <pci.h>
#include <wdmguid.h>
#include <acpiioct.h>

/*
 * Tag used in all pool allocations (Pci Bus)
 */
#define PCI_POOL_TAG 'BicP'

/*
 * Checks if the specified FDO is the FDO for the Root PCI Bus
 */
#define PCI_IS_ROOT_FDO(x) ((x)->BusRootFdoExtension == x)

/*
 * Assertions to make sure we are dealing with the right kind of extension
 */
#define ASSERT_FDO(x) ASSERT((x)->ExtensionType == PciFdoExtensionType);
#define ASSERT_PDO(x) ASSERT((x)->ExtensionType == PciPdoExtensionType);

/*
 * PCI Hack Entry Name Lengths
 */
#define PCI_HACK_ENTRY_SIZE sizeof(L"VVVVdddd") - sizeof(UNICODE_NULL)
#define PCI_HACK_ENTRY_REV_SIZE sizeof(L"VVVVddddRR") - sizeof(UNICODE_NULL)
#define PCI_HACK_ENTRY_SUBSYS_SIZE sizeof(L"VVVVddddssssIIII") - sizeof(UNICODE_NULL)
#define PCI_HACK_ENTRY_FULL_SIZE sizeof(L"VVVVddddssssIIIIRR") - sizeof(UNICODE_NULL)

/*
 * PCI Hack Entry Flags
 */
#define PCI_HACK_HAS_REVISION_INFO 0x01
#define PCI_HACK_HAS_SUBSYSTEM_INFO 0x02

/*
 * PCI Interface Flags
 */
#define PCI_INTERFACE_PDO 0x01
#define PCI_INTERFACE_FDO 0x02
#define PCI_INTERFACE_ROOT 0x04

/*
 * PCI Skip Function Flags
 */
#define PCI_SKIP_DEVICE_ENUMERATION 0x01
#define PCI_SKIP_RESOURCE_ENUMERATION 0x02

/*
 * PCI Apply Hack Flags
 */
#define PCI_HACK_FIXUP_BEFORE_CONFIGURATION 0x00
#define PCI_HACK_FIXUP_AFTER_CONFIGURATION 0x01
#define PCI_HACK_FIXUP_BEFORE_UPDATE 0x03

/*
 * PCI Debugging Device Support
 */
#define MAX_DEBUGGING_DEVICES_SUPPORTED 0x04

/*
 * PCI Driver Verifier Failures
 */
#define PCI_VERIFIER_CODES 0x04

/*
 * Device Extension, Interface, Translator and Arbiter Signatures
 */
typedef enum _PCI_SIGNATURE {
    PciPdoExtensionType = 'icP0',
    PciFdoExtensionType = 'icP1',
    PciArb_Io = 'icP2',
    PciArb_Memory = 'icP3',
    PciArb_Interrupt = 'icP4',
    PciArb_BusNumber = 'icP5',
    PciTrans_Interrupt = 'icP6',
    PciInterface_BusHandler = 'icP7',
    PciInterface_IntRouteHandler = 'icP8',
    PciInterface_PciCb = 'icP9',
    PciInterface_LegacyDeviceDetection = 'icP:',
    PciInterface_PmeHandler = 'icP;',
    PciInterface_DevicePresent = 'icP<',
    PciInterface_NativeIde = 'icP=',
    PciInterface_AgpTarget = 'icP>',
    PciInterface_Location = 'icP?'
} PCI_SIGNATURE, *PPCI_SIGNATURE;

/*
 * Driver-handled PCI Device Types
 */
typedef enum _PCI_DEVICE_TYPES {
    PciTypeInvalid,
    PciTypeHostBridge,
    PciTypePciBridge,
    PciTypeCardbusBridge,
    PciTypeDevice
} PCI_DEVICE_TYPES;

/*
 * Device Extension Logic States
 */
typedef enum _PCI_STATE {
    PciNotStarted,
    PciStarted,
    PciDeleted,
    PciStopped,
    PciSurpriseRemoved,
    PciSynchronizedOperation,
    PciMaxObjectState
} PCI_STATE;

/*
 * IRP Dispatch Logic Style
 */
typedef enum _PCI_DISPATCH_STYLE {
    IRP_COMPLETE,
    IRP_FORWARD,
    IRP_BOTTOM_UP
} PCI_DISPATCH_STYLE;

/*
 * PCI Hack Entry Information
 */
typedef struct _PCI_HACK_ENTRY {
    USHORT VendorID;
    USHORT DeviceID;
    USHORT SubVendorID;
    USHORT SubSystemID;
    ULONGLONG HackFlags;
    USHORT RevisionID;
    UCHAR Flags;
} PCI_HACK_ENTRY, *PPCI_HACK_ENTRY;

/*
 * Power State Information for Device Extension
 */
typedef struct _PCI_POWER_STATE {
    SYSTEM_POWER_STATE CurrentSystemState;
    DEVICE_POWER_STATE CurrentDeviceState;
    SYSTEM_POWER_STATE SystemWakeLevel;
    DEVICE_POWER_STATE DeviceWakeLevel;
    DEVICE_POWER_STATE SystemStateMapping[7];
    PIRP WaitWakeIrp;
    PVOID SavedCancelRoutine;
    LONG Paging;
    LONG Hibernate;
    LONG CrashDump;
} PCI_POWER_STATE, *PPCI_POWER_STATE;

/*
 * Internal PCI Lock Structure
 */
typedef struct _PCI_LOCK {
    LONG Atom;
    BOOLEAN OldIrql;
} PCI_LOCK, *PPCI_LOCK;

/*
 * Device Extension for a Bus FDO
 */
typedef struct _PCI_FDO_EXTENSION {
    SINGLE_LIST_ENTRY List;
    ULONG ExtensionType;
    struct _PCI_MJ_DISPATCH_TABLE *IrpDispatchTable;
    PCI_STATE DeviceState;
    PCI_STATE TentativeNextState;
    PDEVICE_OBJECT PhysicalDeviceObject;
    PDEVICE_OBJECT FunctionalDeviceObject;
    PDEVICE_OBJECT AttachedDeviceObject;
    struct _PCI_PDO_EXTENSION *ChildPdoList;
    struct _PCI_FDO_EXTENSION *BusRootFdoExtension;
    struct _PCI_FDO_EXTENSION *ParentFdoExtension;
    struct _PCI_PDO_EXTENSION *ChildBridgePdoList;
    PHYSICAL_ADDRESS ConfigBase;
    UCHAR BaseBus;
    PCI_POWER_STATE PowerState;
    SINGLE_LIST_ENTRY SecondaryExtension;
    LONG ChildWaitWakeCount;
    PPCI_COMMON_CONFIG PreservedConfig;
    PCI_LOCK Lock;
    struct {
	BOOLEAN Acquired;
	BOOLEAN CacheLineSize;
	BOOLEAN LatencyTimer;
	BOOLEAN EnablePERR;
	BOOLEAN EnableSERR;
    } HotPlugParameters;
    LONG BusHackFlags;
} PCI_FDO_EXTENSION, *PPCI_FDO_EXTENSION;

#define PCI_MAX_RESOURCE_COUNT	(PCI_TYPE0_ADDRESSES + 1)

typedef struct _PCI_FUNCTION_RESOURCES {
    IO_RESOURCE_DESCRIPTOR Limit[PCI_MAX_RESOURCE_COUNT];
    CM_PARTIAL_RESOURCE_DESCRIPTOR Current[PCI_MAX_RESOURCE_COUNT];
} PCI_FUNCTION_RESOURCES, *PPCI_FUNCTION_RESOURCES;

typedef union _PCI_HEADER_TYPE_DEPENDENT {
    struct {
	UCHAR Spare[4];
    } Type0;
    struct {
	UCHAR PrimaryBus;
	UCHAR SecondaryBus;
	UCHAR SubordinateBus;
	UCHAR SubtractiveDecode : 1;
	UCHAR IsaBitSet : 1;
	UCHAR VgaBitSet : 1;
	UCHAR WeChangedBusNumbers : 1;
	UCHAR IsaBitRequired : 1;
    } Type1;
    struct {
	UCHAR Spare[4];
    } Type2;
} PCI_HEADER_TYPE_DEPENDENT, *PPCI_HEADER_TYPE_DEPENDENT;

typedef struct _PCI_PDO_EXTENSION {
    PVOID Next;
    ULONG ExtensionType;
    struct _PCI_MJ_DISPATCH_TABLE *IrpDispatchTable;
    PCI_STATE DeviceState;
    PCI_STATE TentativeNextState;

    PCI_SLOT_NUMBER Slot;
    PDEVICE_OBJECT PhysicalDeviceObject;
    PPCI_FDO_EXTENSION ParentFdoExtension;
    SINGLE_LIST_ENTRY SecondaryExtension;
    LONG BusInterfaceReferenceCount;
    LONG AgpInterfaceReferenceCount;
    USHORT VendorId;
    USHORT DeviceId;
    USHORT SubsystemVendorId;
    USHORT SubsystemId;
    UCHAR RevisionId;
    BOOLEAN ProgIf;
    UCHAR SubClass;
    UCHAR BaseClass;
    UCHAR AdditionalResourceCount;
    UCHAR AdjustedInterruptLine;
    UCHAR InterruptPin;
    UCHAR RawInterruptLine;
    UCHAR CapabilitiesPtr;
    UCHAR SavedLatencyTimer;
    UCHAR SavedCacheLineSize;
    UCHAR HeaderType;
    BOOLEAN NotPresent;
    BOOLEAN ReportedMissing;
    UCHAR ExpectedWritebackFailure;
    BOOLEAN NoTouchPmeEnable;
    BOOLEAN LegacyDriver;
    BOOLEAN UpdateHardware;
    BOOLEAN MovedDevice;
    BOOLEAN DisablePowerDown;
    BOOLEAN NeedsHotPlugConfiguration;
    BOOLEAN IDEInNativeMode;
    BOOLEAN BIOSAllowsIDESwitchToNativeMode;
    BOOLEAN IoSpaceUnderNativeIdeControl;
    BOOLEAN OnDebugPath;
    BOOLEAN IoSpaceNotRequired;
    PCI_HARDWARE_INTERFACE InterfaceType;
    PCI_POWER_STATE PowerState;
    PCI_HEADER_TYPE_DEPENDENT Dependent;
    ULONGLONG HackFlags;
    PCI_FUNCTION_RESOURCES *Resources;
    PCI_FDO_EXTENSION *BridgeFdoExtension;
    struct _PCI_PDO_EXTENSION *NextBridge;
    struct _PCI_PDO_EXTENSION *NextHashEntry;
    PCI_LOCK Lock;
    PCI_PMC PowerCapabilities;
    UCHAR TargetAgpCapabilityId;
    USHORT CommandEnables;
    USHORT InitialCommand;
} PCI_PDO_EXTENSION, *PPCI_PDO_EXTENSION;

/*
 * IRP Dispatch Function Type
 */
typedef NTSTATUS (*PCI_DISPATCH_FUNCTION)(IN PIRP Irp,
					       IN PIO_STACK_LOCATION IoStackLocation,
					       IN PVOID DeviceExtension);

/*
 * IRP Dispatch Minor Table
 */
typedef struct _PCI_MN_DISPATCH_TABLE {
    PCI_DISPATCH_STYLE DispatchStyle;
    PCI_DISPATCH_FUNCTION DispatchFunction;
} PCI_MN_DISPATCH_TABLE, *PPCI_MN_DISPATCH_TABLE;

/*
 * IRP Dispatch Major Table
 */
typedef struct _PCI_MJ_DISPATCH_TABLE {
    ULONG PnpIrpMaximumMinorFunction;
    PPCI_MN_DISPATCH_TABLE PnpIrpDispatchTable;
    ULONG PowerIrpMaximumMinorFunction;
    PPCI_MN_DISPATCH_TABLE PowerIrpDispatchTable;
    PCI_DISPATCH_STYLE SystemControlIrpDispatchStyle;
    PCI_DISPATCH_FUNCTION SystemControlIrpDispatchFunction;
    PCI_DISPATCH_STYLE OtherIrpDispatchStyle;
    PCI_DISPATCH_FUNCTION OtherIrpDispatchFunction;
} PCI_MJ_DISPATCH_TABLE, *PPCI_MJ_DISPATCH_TABLE;

/*
 * PCI ID Buffer Descriptor
 */
typedef struct _PCI_ID_BUFFER {
    ULONG TotalWchars;
    WCHAR BufferData[512];
} PCI_ID_BUFFER, *PPCI_ID_BUFFER;

/*
 * PCI Configuration Callbacks
 */
struct _PCI_CONFIGURATOR_CONTEXT;

typedef VOID (*PCI_CONFIGURATOR_INITIALIZE)(
    IN struct _PCI_CONFIGURATOR_CONTEXT *Context);

typedef VOID (*PCI_CONFIGURATOR_RESTORE_CURRENT)(
    IN struct _PCI_CONFIGURATOR_CONTEXT *Context);

typedef VOID (*PCI_CONFIGURATOR_SAVE_LIMITS)(
    IN struct _PCI_CONFIGURATOR_CONTEXT *Context);

typedef VOID (*PCI_CONFIGURATOR_SAVE_CURRENT_SETTINGS)(
    IN struct _PCI_CONFIGURATOR_CONTEXT *Context);

typedef VOID (*PCI_CONFIGURATOR_CHANGE_RESOURCE_SETTINGS)(
    IN PPCI_PDO_EXTENSION PdoExtension, IN PPCI_COMMON_HEADER PciData);

typedef VOID (*PCI_CONFIGURATOR_GET_ADDITIONAL_RESOURCE_DESCRIPTORS)(
    IN struct _PCI_CONFIGURATOR_CONTEXT *Context, IN PPCI_COMMON_HEADER PciData,
    IN PIO_RESOURCE_DESCRIPTOR IoDescriptor);

typedef VOID (*PCI_CONFIGURATOR_RESET_DEVICE)(IN PPCI_PDO_EXTENSION PdoExtension,
						   IN PPCI_COMMON_HEADER PciData);

/*
 * PCI Configurator
 */
typedef struct _PCI_CONFIGURATOR {
    PCI_CONFIGURATOR_INITIALIZE Initialize;
    PCI_CONFIGURATOR_RESTORE_CURRENT RestoreCurrent;
    PCI_CONFIGURATOR_SAVE_LIMITS SaveLimits;
    PCI_CONFIGURATOR_SAVE_CURRENT_SETTINGS SaveCurrentSettings;
    PCI_CONFIGURATOR_CHANGE_RESOURCE_SETTINGS ChangeResourceSettings;
    PCI_CONFIGURATOR_GET_ADDITIONAL_RESOURCE_DESCRIPTORS GetAdditionalResourceDescriptors;
    PCI_CONFIGURATOR_RESET_DEVICE ResetDevice;
} PCI_CONFIGURATOR, *PPCI_CONFIGURATOR;

/*
 * PCI Configurator Context
 */
typedef struct _PCI_CONFIGURATOR_CONTEXT {
    PPCI_PDO_EXTENSION PdoExtension;
    PPCI_COMMON_HEADER Current;
    PPCI_COMMON_HEADER PciData;
    PPCI_CONFIGURATOR Configurator;
    USHORT SecondaryStatus;
    USHORT Status;
    USHORT Command;
} PCI_CONFIGURATOR_CONTEXT, *PPCI_CONFIGURATOR_CONTEXT;

/*
 * PCI IPI Function
 */
typedef VOID (*PCI_IPI_FUNCTION)(IN PVOID Reserved, IN PVOID Context);

/*
 * PCI IPI Context
 */
typedef struct _PCI_IPI_CONTEXT {
    LONG RunCount;
    ULONG Barrier;
    PVOID DeviceExtension;
    PCI_IPI_FUNCTION Function;
    PVOID Context;
} PCI_IPI_CONTEXT, *PPCI_IPI_CONTEXT;

/*
 * PCI Legacy Device Location Cache
 */
typedef struct _PCI_LEGACY_DEVICE {
    struct _PCI_LEGACY_DEVICE *Next;
    PDEVICE_OBJECT DeviceObject;
    ULONG BusNumber;
    ULONG SlotNumber;
    UCHAR InterruptLine;
    UCHAR InterruptPin;
    UCHAR BaseClass;
    UCHAR SubClass;
    PDEVICE_OBJECT PhysicalDeviceObject;
    PPCI_PDO_EXTENSION PdoExtension;
} PCI_LEGACY_DEVICE, *PPCI_LEGACY_DEVICE;

/*
 * Device private data types in the IO resource descriptor
 */
typedef enum _PCI_DEVICE_PRIVATE_TYPE {
    PciInvalidDevicePrivateType,
    PciLockResource, /* Do not change the following resources in PciComputeNewSettings */
    PciBarIndex	/* Specifies the corresponding BAR index of the previous resource */
} PCI_DEVICE_PRIVATE_TYPE;

/*
 * IRP Dispatch Routines
 */

DRIVER_DISPATCH PciDispatchIrp;

NTAPI NTSTATUS PciDispatchIrp(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

NTSTATUS PciIrpNotSupported(IN PIRP Irp, IN PIO_STACK_LOCATION IoStackLocation,
			    IN PPCI_FDO_EXTENSION DeviceExtension);

NTSTATUS PciIrpInvalidDeviceRequest(IN PIRP Irp,
				    IN PIO_STACK_LOCATION IoStackLocation,
				    IN PPCI_FDO_EXTENSION DeviceExtension);

/*
 * Power Routines
 */
NTSTATUS PciFdoWaitWake(IN PIRP Irp, IN PIO_STACK_LOCATION IoStackLocation,
			IN PPCI_FDO_EXTENSION DeviceExtension);

NTSTATUS PciFdoSetPowerState(IN PIRP Irp, IN PIO_STACK_LOCATION IoStackLocation,
			     IN PPCI_FDO_EXTENSION DeviceExtension);

NTSTATUS PciFdoIrpQueryPower(IN PIRP Irp, IN PIO_STACK_LOCATION IoStackLocation,
			     IN PPCI_FDO_EXTENSION DeviceExtension);

NTSTATUS PciSetPowerManagedDevicePowerState(IN PPCI_PDO_EXTENSION DeviceExtension,
					    IN DEVICE_POWER_STATE DeviceState,
					    IN BOOLEAN IrpSet);

/*
 * Bus FDO Routines
 */

DRIVER_ADD_DEVICE PciAddDevice;

NTAPI NTSTATUS PciAddDevice(IN PDRIVER_OBJECT DriverObject,
			    IN PDEVICE_OBJECT PhysicalDeviceObject);

/*
 * Device PDO Routines
 */
NTSTATUS PciPdoCreate(IN PPCI_FDO_EXTENSION DeviceExtension,
		      IN PCI_SLOT_NUMBER Slot, OUT PDEVICE_OBJECT *PdoDeviceObject);
VOID PciPdoDestroy(IN PDEVICE_OBJECT Pdo);

/*
 * Utility Routines
 */
BOOLEAN PciStringToUSHORT(IN PWCHAR String, OUT PUSHORT Value);

BOOLEAN PciIsDatacenter(VOID);

NTSTATUS PciBuildDefaultExclusionLists(VOID);

BOOLEAN PciUnicodeStringStrStr(IN PUNICODE_STRING InputString,
			       IN PCUNICODE_STRING EqualString,
			       IN BOOLEAN CaseInSensitive);

BOOLEAN PciOpenKey(IN PWCHAR KeyName, IN HANDLE RootKey,
		   IN ACCESS_MASK DesiredAccess, OUT PHANDLE KeyHandle,
		   OUT PNTSTATUS KeyStatus);

NTSTATUS PciGetRegistryValue(IN PWCHAR ValueName, IN PWCHAR KeyName,
			     IN HANDLE RootHandle, IN ULONG Type,
			     OUT PVOID *OutputBuffer, OUT PULONG OutputLength);

PPCI_FDO_EXTENSION PciFindParentPciFdoExtension(IN PDEVICE_OBJECT DeviceObject);

VOID PciInsertEntryAtTail(IN PSINGLE_LIST_ENTRY ListHead,
			  IN PPCI_FDO_EXTENSION DeviceExtension);

VOID PciRemoveEntryFromList(IN PSINGLE_LIST_ENTRY ListHead,
			    IN PSINGLE_LIST_ENTRY Entry);

NTSTATUS PciSendIoctl(IN PDEVICE_OBJECT DeviceObject, IN ULONG IoControlCode,
		      IN PVOID InputBuffer, IN ULONG InputBufferLength,
		      IN PVOID OutputBuffer, IN ULONG OutputBufferLength);

ULONGLONG PciGetHackFlags(IN USHORT VendorId, IN USHORT DeviceId,
			  IN USHORT SubVendorId, IN USHORT SubSystemId,
			  IN UCHAR RevisionId);

PPCI_PDO_EXTENSION PciFindPdoByFunction(IN PPCI_FDO_EXTENSION DeviceExtension,
					IN ULONG FunctionNumber,
					IN PPCI_COMMON_HEADER PciData);

BOOLEAN PciIsCriticalDeviceClass(IN UCHAR BaseClass, IN UCHAR SubClass);

BOOLEAN PciIsDeviceOnDebugPath(IN PPCI_PDO_EXTENSION DeviceExtension);

NTSTATUS PciGetBiosConfig(IN PPCI_PDO_EXTENSION DeviceExtension,
			  OUT PPCI_COMMON_HEADER PciData);

NTSTATUS PciSaveBiosConfig(IN PPCI_PDO_EXTENSION DeviceExtension,
			   OUT PPCI_COMMON_HEADER PciData);

UCHAR PciReadDeviceCapability(IN PPCI_PDO_EXTENSION DeviceExtension,
			      IN UCHAR Offset, IN ULONG CapabilityId,
			      OUT PPCI_CAPABILITIES_HEADER Buffer, IN ULONG Length);

BOOLEAN PciCanDisableDecodes(IN PPCI_PDO_EXTENSION DeviceExtension,
			     IN PPCI_COMMON_HEADER Config, IN ULONGLONG HackFlags,
			     IN BOOLEAN ForPowerDown);

PCI_DEVICE_TYPES PciClassifyDeviceType(IN PPCI_PDO_EXTENSION PdoExtension);

BOOLEAN PciCreateIoDescriptorFromBarLimit(PIO_RESOURCE_DESCRIPTOR ResourceDescriptor,
					  IN PULONG BarArray, IN BOOLEAN Rom);

BOOLEAN PciIsSlotPresentInParentMethod(IN PPCI_PDO_EXTENSION PdoExtension,
				       IN ULONG Method);

VOID PciDecodeEnable(IN PPCI_PDO_EXTENSION PdoExtension, IN BOOLEAN Enable,
		     OUT PUSHORT Command);

NTSTATUS PciQueryBusInformation(IN PPCI_PDO_EXTENSION PdoExtension,
				IN PPNP_BUS_INFORMATION *Buffer);

NTSTATUS PciQueryCapabilities(IN PPCI_PDO_EXTENSION PdoExtension,
			      IN OUT PDEVICE_CAPABILITIES DeviceCapability);

/*
 * Configuration Routines
 */
VOID PciReadSlotConfig(IN PPCI_FDO_EXTENSION DeviceExtension,
		       IN PCI_SLOT_NUMBER Slot, IN PVOID Buffer, IN ULONG Offset,
		       IN ULONG Length);

VOID PciWriteDeviceConfig(IN PPCI_PDO_EXTENSION DeviceExtension, IN PVOID Buffer,
			  IN ULONG Offset, IN ULONG Length);

VOID PciReadDeviceConfig(IN PPCI_PDO_EXTENSION DeviceExtension, IN PVOID Buffer,
			 IN ULONG Offset, IN ULONG Length);

UCHAR PciGetAdjustedInterruptLine(IN PPCI_PDO_EXTENSION PdoExtension);

/*
 * State Machine Logic Transition Routines
 */
VOID PciInitializeState(IN PPCI_FDO_EXTENSION DeviceExtension);

NTSTATUS PciBeginStateTransition(IN PPCI_FDO_EXTENSION DeviceExtension,
				 IN PCI_STATE NewState);

NTSTATUS PciCancelStateTransition(IN PPCI_FDO_EXTENSION DeviceExtension,
				  IN PCI_STATE NewState);

VOID PciCommitStateTransition(IN PPCI_FDO_EXTENSION DeviceExtension,
			      IN PCI_STATE NewState);

/*
 * Debug Helpers
 */
BOOLEAN PciDebugIrpDispatchDisplay(IN PIO_STACK_LOCATION IoStackLocation,
				   IN PPCI_FDO_EXTENSION DeviceExtension,
				   IN USHORT MaxMinor);

VOID PciDebugDumpCommonConfig(IN PPCI_COMMON_HEADER PciData);

VOID PciDebugDumpQueryCapabilities(IN PDEVICE_CAPABILITIES DeviceCaps);

FORCEINLINE VOID PciDebugPrintIoResReqList(IN PIO_RESOURCE_REQUIREMENTS_LIST Requirements)
{
    IoDbgPrintResouceRequirementsList(Requirements);
}

FORCEINLINE VOID PciDebugPrintCmResList(IN PCM_RESOURCE_LIST ResourceList)
{
    CmDbgPrintResourceList(ResourceList);
}

FORCEINLINE VOID PciDebugPrintPartialResource(IN PCM_PARTIAL_RESOURCE_DESCRIPTOR Res)
{
    CmDbgPrintResourceDescriptor(Res);
}

/*
 * PCI Enumeration and Resources
 */
NTSTATUS PciQueryDeviceRelations(IN PPCI_FDO_EXTENSION DeviceExtension,
				 IN OUT PDEVICE_RELATIONS *DeviceRelations);

NTSTATUS PciQueryResources(IN PPCI_PDO_EXTENSION PdoExtension,
			   OUT PCM_RESOURCE_LIST *Buffer);

NTSTATUS PciQueryTargetDeviceRelations(IN PPCI_PDO_EXTENSION PdoExtension,
				       IN OUT PDEVICE_RELATIONS *DeviceRelations);

NTSTATUS PciQueryEjectionRelations(IN PPCI_PDO_EXTENSION PdoExtension,
				   IN OUT PDEVICE_RELATIONS *DeviceRelations);

NTSTATUS PciQueryRequirements(IN PPCI_PDO_EXTENSION PdoExtension,
			      IN OUT PIO_RESOURCE_REQUIREMENTS_LIST *RequirementsList);

BOOLEAN PciComputeNewCurrentSettings(IN PPCI_PDO_EXTENSION PdoExtension,
				     IN PCM_RESOURCE_LIST ResourceList);

NTSTATUS PciSetResources(IN PPCI_PDO_EXTENSION PdoExtension, IN BOOLEAN DoReset);

/*
 * Identification Functions
 */
PWCHAR PciGetDeviceDescriptionMessage(IN UCHAR BaseClass, IN UCHAR SubClass);

NTSTATUS PciQueryDeviceText(IN PPCI_PDO_EXTENSION PdoExtension,
			    IN DEVICE_TEXT_TYPE QueryType, IN ULONG Locale,
			    OUT PWCHAR *Buffer);

NTSTATUS PciQueryId(IN PPCI_PDO_EXTENSION DeviceExtension,
		    IN BUS_QUERY_ID_TYPE QueryType, OUT PWCHAR *Buffer);

/*
 * CardBUS Support
 */
VOID Cardbus_MassageHeaderForLimitsDetermination(IN PPCI_CONFIGURATOR_CONTEXT Context);

VOID Cardbus_SaveCurrentSettings(IN PPCI_CONFIGURATOR_CONTEXT Context);

VOID Cardbus_SaveLimits(IN PPCI_CONFIGURATOR_CONTEXT Context);

VOID Cardbus_RestoreCurrent(IN PPCI_CONFIGURATOR_CONTEXT Context);

VOID Cardbus_GetAdditionalResourceDescriptors(IN PPCI_CONFIGURATOR_CONTEXT Context,
					      IN PPCI_COMMON_HEADER PciData,
					      IN PIO_RESOURCE_DESCRIPTOR IoDescriptor);

VOID Cardbus_ResetDevice(IN PPCI_PDO_EXTENSION PdoExtension,
			 IN PPCI_COMMON_HEADER PciData);

VOID Cardbus_ChangeResourceSettings(IN PPCI_PDO_EXTENSION PdoExtension,
				    IN PPCI_COMMON_HEADER PciData);

/*
 * PCI Device Support
 */
VOID Device_MassageHeaderForLimitsDetermination(IN PPCI_CONFIGURATOR_CONTEXT Context);

VOID Device_SaveCurrentSettings(IN PPCI_CONFIGURATOR_CONTEXT Context);

VOID Device_SaveLimits(IN PPCI_CONFIGURATOR_CONTEXT Context);

VOID Device_RestoreCurrent(IN PPCI_CONFIGURATOR_CONTEXT Context);

VOID Device_GetAdditionalResourceDescriptors(IN PPCI_CONFIGURATOR_CONTEXT Context,
					     IN PPCI_COMMON_HEADER PciData,
					     IN PIO_RESOURCE_DESCRIPTOR IoDescriptor);

VOID Device_ResetDevice(IN PPCI_PDO_EXTENSION PdoExtension,
			IN PPCI_COMMON_HEADER PciData);

VOID Device_ChangeResourceSettings(IN PPCI_PDO_EXTENSION PdoExtension,
				   IN PPCI_COMMON_HEADER PciData);

/*
 * PCI-to-PCI Bridge Device Support
 */
VOID PCIBridge_MassageHeaderForLimitsDetermination(IN PPCI_CONFIGURATOR_CONTEXT Context);

VOID PCIBridge_SaveCurrentSettings(IN PPCI_CONFIGURATOR_CONTEXT Context);

VOID PCIBridge_SaveLimits(IN PPCI_CONFIGURATOR_CONTEXT Context);

VOID PCIBridge_RestoreCurrent(IN PPCI_CONFIGURATOR_CONTEXT Context);

VOID PCIBridge_GetAdditionalResourceDescriptors(IN PPCI_CONFIGURATOR_CONTEXT Context,
						IN PPCI_COMMON_HEADER PciData,
						IN PIO_RESOURCE_DESCRIPTOR IoDescriptor);

VOID PCIBridge_ResetDevice(IN PPCI_PDO_EXTENSION PdoExtension,
			   IN PPCI_COMMON_HEADER PciData);

VOID PCIBridge_ChangeResourceSettings(IN PPCI_PDO_EXTENSION PdoExtension,
				      IN PPCI_COMMON_HEADER PciData);

/*
 * Bus Number Routines
 */
BOOLEAN PciAreBusNumbersConfigured(IN PPCI_PDO_EXTENSION PdoExtension);

/*
 * External Resources
 */
extern SINGLE_LIST_ENTRY PciFdoExtensionListHead;
extern PDRIVER_OBJECT PciDriverObject;
extern PPCI_HACK_ENTRY PciHackTable;
extern BOOLEAN PciLockDeviceResources;
extern BOOLEAN PciAssignBusNumbers;
extern PPCI_IRQ_ROUTING_TABLE PciIrqRoutingTable;
extern BOOLEAN PciRunningDatacenter;

#endif /* _PCIDRV_H_ */
