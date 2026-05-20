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
 * Device Extension for a Bus FDO.
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
} PCI_FDO_EXTENSION, *PPCI_FDO_EXTENSION;

/*
 * Maximum number of IO resources we need to handle for a PCI function
 *
 * Type 0 (PCI Endpoints) headers have the most number of resources
 * (6 BARs plus one expansion ROM base address). Type 1 (PCI bridge)
 * has 2 BARs, a forwarded IO window, a non-prefetchable memory window,
 * a prefetchable memory window, and expansion ROM base address (so six
 * in total). Type 2 (Cardbus bridge) has 4 BARs, cardbus socket base
 * address, and 16-bit legacy mode base address, so also six in total.
 */
#define PCI_MAX_RESOURCE_COUNT	(PCI_TYPE0_ADDRESSES + 1)

/*
 * The IO resources for a PCI bridge is ordered in the following way:
 * First the two BAR resources, followed by the IO port forward window,
 * the non-prefetchable memory window, the prefetchable memory window,
 * in this order, and finally the ROM address.
 */
#define PCI_BRIDGE_RESOURCE_COUNT	(PCI_TYPE1_ADDRESSES + 3 + 1)
#define PCI_BRIDGE_IO_PORT_RESOURCE	(PCI_TYPE1_ADDRESSES)
#define PCI_BRIDGE_MEMORY_RESOURCE	(PCI_TYPE1_ADDRESSES + 1)

typedef struct _PCI_FUNCTION_RESOURCES {
    IO_RESOURCE_DESCRIPTOR Limit[PCI_MAX_RESOURCE_COUNT];
    CM_PARTIAL_RESOURCE_DESCRIPTOR Current[PCI_MAX_RESOURCE_COUNT];
} PCI_FUNCTION_RESOURCES, *PPCI_FUNCTION_RESOURCES;

typedef struct _PCI_INTERRUPT_RESOURCE {
    CM_PARTIAL_RESOURCE_DESCRIPTOR Raw;
    CM_PARTIAL_RESOURCE_DESCRIPTOR Translated;
} PCI_INTERRUPT_RESOURCE, *PPCI_INTERRUPT_RESOURCE;

typedef struct _PCI_MSI_INFO {
    BOOLEAN ExtendedMessage;	/* TRUE if device supports MSI-X */
    UCHAR CapabilityOffset;	/* Offset of MSI(X) capability in config space */
    union {
	struct {
	    PCI_MSI_MESSAGE_CONTROL MessageControl;
	    LARGE_INTEGER MessageAddress;
	    USHORT MessageData;
	    ULONG MaskBits;
	    ULONG PendingBits;
	} MessageInfo;
	struct {
	    PCI_MSIX_MESSAGE_CONTROL MessageControl;
	    ULONG MessageTable;
	    ULONG PendingBitArray;
	} ExtendedMessageInfo;
    };
} PCI_MSI_INFO, *PPCI_MSI_INFO;

typedef struct _PCI_PDO_EXTENSION {
    PVOID Next;
    ULONG ExtensionType;
    struct _PCI_MJ_DISPATCH_TABLE *IrpDispatchTable;
    PCI_STATE DeviceState;
    PCI_STATE TentativeNextState;

    PCI_SLOT_NUMBER Slot;
    PDEVICE_OBJECT PhysicalDeviceObject;
    volatile UCHAR *MappedConfigSpace;
    PPCI_FDO_EXTENSION ParentFdoExtension; /* FDO of the PCI bridge this PDO is under. */
    USHORT VendorId;
    USHORT DeviceId;
    USHORT SubsystemVendorId;
    USHORT SubsystemId;
    UCHAR RevisionId;
    UCHAR ProgIf;
    UCHAR SubClass;
    UCHAR BaseClass;
    UCHAR AdditionalResourceCount;
    UCHAR CapabilitiesPtr;
    UCHAR HeaderType;
    BOOLEAN NotPresent;
    BOOLEAN NoPmCaps;
    PCI_HARDWARE_INTERFACE InterfaceType;
    PCI_POWER_STATE PowerState;
    struct {
	UCHAR PrimaryBus;
	UCHAR SecondaryBus;
	UCHAR SubordinateBus;
	BOOLEAN SubtractiveDecode;
	BOOLEAN VgaBitSet;
    } BridgeInfo;
    PCI_MSI_INFO MsiInfo;
    ULONG InterruptResourceCount;
    PPCI_INTERRUPT_RESOURCE InterruptResources;
    PPCI_FUNCTION_RESOURCES Resources;
    struct _PCI_PDO_EXTENSION *NextBridge;
    PCI_PMC PowerCapabilities;
    UCHAR TargetAgpCapabilityId;
} PCI_PDO_EXTENSION, *PPCI_PDO_EXTENSION;

FORCEINLINE ULONG PciGetShareDisposition(IN PPCI_PDO_EXTENSION PdoExt)
{
    if (PCI_IS_ROOT_FDO(PdoExt->ParentFdoExtension)) {
	return CmResourceShareDeviceExclusive;
    } else {
	return CmResourceShareBusShared;
    }
}

FORCEINLINE PCM_PARTIAL_RESOURCE_DESCRIPTOR
PciGetBridgeForwardWindow(IN PPCI_PDO_EXTENSION PdoExtension,
			  IN ULONG Type,
			  IN ULONG Flags)
{
    PPCI_FDO_EXTENSION BridgeFdo = PdoExtension->ParentFdoExtension;
    PDEVICE_OBJECT BridgePdo = BridgeFdo->PhysicalDeviceObject;
    PPCI_PDO_EXTENSION BridgeExt = BridgePdo->DeviceExtension;
    ULONG Idx = 0;
    if (Type == CmResourceTypePort) {
	Idx = PCI_BRIDGE_IO_PORT_RESOURCE;
    } else {
	Idx = PCI_BRIDGE_MEMORY_RESOURCE;
	if (Flags & CM_RESOURCE_MEMORY_PREFETCHABLE) {
	    Idx++;
	}
    }
    return &BridgeExt->Resources->Current[Idx];
}

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
typedef VOID (*PCI_MASSAGE_HEADER_FOR_LIMITS_DETERMINATION)(OUT PPCI_COMMON_HEADER Cfg);
typedef VOID (*PCI_READ_RESOURCES)(IN PPCI_PDO_EXTENSION PdoExt,
				   OUT PPCI_COMMON_HEADER Cfg);
typedef VOID (*PCI_WRITE_RESOURCES)(IN PPCI_PDO_EXTENSION PdoExt,
				    IN PPCI_COMMON_HEADER Cfg);
typedef VOID (*PCI_SAVE_LIMITS)(IN PPCI_PDO_EXTENSION PdoExtension,
				IN PPCI_COMMON_HEADER Cfg);
typedef VOID (*PCI_SAVE_CURRENT_SETTINGS)(IN PPCI_PDO_EXTENSION PdoExtension,
					  IN PPCI_COMMON_HEADER Cfg);
typedef VOID (*PCI_CONFIGURATOR_CHANGE_RESOURCE_SETTINGS)(IN PPCI_PDO_EXTENSION PdoExt,
							  OUT USHORT *CommandEnables);
typedef VOID (*PCI_CONFIGURATOR_GET_ADDITIONAL_RESOURCE_DESCRIPTORS)(
    IN PPCI_PDO_EXTENSION PdoExt,
    IN PIO_RESOURCE_DESCRIPTOR IoDescriptor);
typedef VOID (*PCI_CONFIGURATOR_RESET_DEVICE)(IN PPCI_PDO_EXTENSION PdoExt);

/*
 * PCI Configurator
 */
typedef struct _PCI_CONFIGURATOR {
    PCI_MASSAGE_HEADER_FOR_LIMITS_DETERMINATION MassageHeaderForLimitsDetermination;
    PCI_READ_RESOURCES ReadResources;
    PCI_WRITE_RESOURCES WriteResources;
    PCI_SAVE_LIMITS SaveLimits;
    PCI_SAVE_CURRENT_SETTINGS SaveCurrentSettings;
    PCI_CONFIGURATOR_CHANGE_RESOURCE_SETTINGS ChangeResourceSettings;
    PCI_CONFIGURATOR_GET_ADDITIONAL_RESOURCE_DESCRIPTORS GetAdditionalResourceDescriptors;
    PCI_CONFIGURATOR_RESET_DEVICE ResetDevice;
} PCI_CONFIGURATOR, *PPCI_CONFIGURATOR;

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
					    IN DEVICE_POWER_STATE DeviceState);

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
VOID PciInsertEntryAtTail(IN PSINGLE_LIST_ENTRY ListHead,
			  IN PPCI_FDO_EXTENSION DeviceExtension);

NTSTATUS PciSendIoctl(IN PDEVICE_OBJECT DeviceObject, IN ULONG IoControlCode,
		      IN PVOID InputBuffer, IN ULONG InputBufferLength,
		      IN PVOID OutputBuffer, IN ULONG OutputBufferLength);

UCHAR PciReadDeviceCapability(IN PPCI_PDO_EXTENSION DeviceExtension,
			      IN UCHAR Offset, IN ULONG CapabilityId,
			      OUT PPCI_CAPABILITIES_HEADER Buffer, IN ULONG Length);

BOOLEAN PciCreateIoDescriptorFromBarLimit(IN PPCI_PDO_EXTENSION PdoExt,
					  OUT PIO_RESOURCE_DESCRIPTOR ResourceDescriptor,
					  IN PULONG BarArray, IN BOOLEAN Rom);

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

VOID PciSetCommand(IN PPCI_PDO_EXTENSION PdoExtension, IN USHORT CommandBits,
		   IN BOOLEAN Enable);

#define PCI_READ_CONFIG(DevExt, PciData, Field)			\
    PciReadDeviceConfig(DevExt, &((PciData)->Field),		\
			FIELD_OFFSET(PCI_COMMON_HEADER, Field), \
			sizeof((PciData)->Field))

#define PCI_WRITE_CONFIG(DevExt, PciData, Field)			\
    PciWriteDeviceConfig(DevExt, &((PciData)->Field),			\
			 FIELD_OFFSET(PCI_COMMON_HEADER, Field),	\
			 sizeof((PciData)->Field))

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

VOID PciDebugDumpResources(IN PPCI_PDO_EXTENSION PdoExt);

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
 * Id String Helper Functions
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
VOID Cardbus_MassageHeaderForLimitsDetermination(OUT PPCI_COMMON_HEADER Cfg);

VOID Cardbus_ReadResources(IN PPCI_PDO_EXTENSION PdoExt,
			   OUT PPCI_COMMON_HEADER Cfg);

VOID Cardbus_WriteResources(IN PPCI_PDO_EXTENSION PdoExt,
			    IN PPCI_COMMON_HEADER Cfg);

VOID Cardbus_SaveLimits(IN PPCI_PDO_EXTENSION PdoExtension,
			IN PPCI_COMMON_HEADER Cfg);

VOID Cardbus_SaveCurrentSettings(IN PPCI_PDO_EXTENSION PdoExtension,
				 IN PPCI_COMMON_HEADER Cfg);

VOID Cardbus_GetAdditionalResourceDescriptors(IN PPCI_PDO_EXTENSION PdoExt,
					      IN PIO_RESOURCE_DESCRIPTOR IoDescriptor);

VOID Cardbus_ResetDevice(IN PPCI_PDO_EXTENSION PdoExtension);

VOID Cardbus_ChangeResourceSettings(IN PPCI_PDO_EXTENSION PdoExtension,
				    OUT USHORT *CommandEnables);

/*
 * PCI Device Support
 */
VOID Device_MassageHeaderForLimitsDetermination(OUT PPCI_COMMON_HEADER Cfg);

VOID Device_ReadResources(IN PPCI_PDO_EXTENSION PdoExt,
			  OUT PPCI_COMMON_HEADER Cfg);

VOID Device_WriteResources(IN PPCI_PDO_EXTENSION PdoExt,
			   IN PPCI_COMMON_HEADER Cfg);

VOID Device_SaveLimits(IN PPCI_PDO_EXTENSION PdoExtension,
		       IN PPCI_COMMON_HEADER Cfg);

VOID Device_SaveCurrentSettings(IN PPCI_PDO_EXTENSION PdoExtension,
				IN PPCI_COMMON_HEADER Cfg);

VOID Device_GetAdditionalResourceDescriptors(IN PPCI_PDO_EXTENSION PdoExt,
					     IN PIO_RESOURCE_DESCRIPTOR IoDescriptor);

VOID Device_ResetDevice(IN PPCI_PDO_EXTENSION PdoExtension);

VOID Device_ChangeResourceSettings(IN PPCI_PDO_EXTENSION PdoExtension,
				   OUT USHORT *CommandEnables);

/*
 * PCI-to-PCI Bridge Device Support
 */
VOID PCIBridge_MassageHeaderForLimitsDetermination(OUT PPCI_COMMON_HEADER Cfg);

VOID PCIBridge_ReadResources(IN PPCI_PDO_EXTENSION PdoExt,
			     OUT PPCI_COMMON_HEADER Cfg);

VOID PCIBridge_WriteResources(IN PPCI_PDO_EXTENSION PdoExt,
			      IN PPCI_COMMON_HEADER Cfg);

VOID PCIBridge_SaveLimits(IN PPCI_PDO_EXTENSION PdoExtension,
			  IN PPCI_COMMON_HEADER Cfg);

VOID PCIBridge_SaveCurrentSettings(IN PPCI_PDO_EXTENSION PdoExtension,
				   IN PPCI_COMMON_HEADER Cfg);

VOID PCIBridge_GetAdditionalResourceDescriptors(IN PPCI_PDO_EXTENSION PdoExt,
						IN PIO_RESOURCE_DESCRIPTOR IoDescriptor);

VOID PCIBridge_ResetDevice(IN PPCI_PDO_EXTENSION PdoExtension);

VOID PCIBridge_ChangeResourceSettings(IN PPCI_PDO_EXTENSION PdoExtension,
				      OUT USHORT *CommandEnables);

/*
 * External Resources
 */
extern SINGLE_LIST_ENTRY PciFdoExtensionListHead;
extern PDRIVER_OBJECT PciDriverObject;
extern PCI_CONFIGURATOR PciConfigurators[];

#endif /* _PCIDRV_H_ */
