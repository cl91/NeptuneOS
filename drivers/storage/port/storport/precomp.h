/*
 * PROJECT:     ReactOS Storport Driver
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Storport driver common header file
 * COPYRIGHT:   Copyright 2017 Eric Kohl (eric.kohl@reactos.org)
 */

#ifndef _STORPORT_PCH_
#define _STORPORT_PCH_

#include <ntddk.h>

/* Declare STORPORT_API functions as exports rather than imports */
#define _STORPORT_
#include <storport.h>

#include <ntddscsi.h>
#include <ntdddisk.h>
#include <ntddstor.h>
#include <mountdev.h>
#include <wdmguid.h>

/* Memory Tags */
#define TAG_GLOBAL_DATA     'DGtS'
#define TAG_INIT_DATA       'DItS'
#define TAG_MINIPORT_DATA   'DMtS'
#define TAG_PORT_CONTEXT    'CPtS'
#define TAG_MDL             'DMtS'
#define TAG_SRB_EXTENSION   'EStS'
#define TAG_ACCRESS_RANGE   'RAtS'
#define TAG_RESOURCE_LIST   'LRtS'
#define TAG_ADDRESS_MAPPING 'MAtS'
#define TAG_INQUIRY_DATA    'QItS'
#define TAG_SENSE_DATA      'NStS'
#define TAG_LUN_LIST        'LLtS'
#define TAG_DEV_RELATIONS   'RDtS'

typedef enum {
    dsStopped,
    dsStarted,
    dsPaused,
    dsRemoved,
    dsSurpriseRemoved
} DEVICE_STATE;

typedef enum {
    InvalidExtension = 0,
    DriverExtension,
    FdoExtension,
    PdoExtension
} EXTENSION_TYPE;

typedef struct _DRIVER_INIT_DATA {
    LIST_ENTRY Entry;
    HW_INITIALIZATION_DATA HwInitData;
} DRIVER_INIT_DATA, *PDRIVER_INIT_DATA;

typedef struct _DRIVER_OBJECT_EXTENSION {
    EXTENSION_TYPE ExtensionType;
    PDRIVER_OBJECT DriverObject;

    LIST_ENTRY AdapterListHead;
    ULONG AdapterCount;
    STORAGE_BUS_TYPE StorageBusType;

    LIST_ENTRY InitDataListHead;
} DRIVER_OBJECT_EXTENSION, *PDRIVER_OBJECT_EXTENSION;

typedef struct _MINIPORT_DEVICE_EXTENSION {
    struct _MINIPORT *Miniport;
    UCHAR HwDeviceExtension[0];
} MINIPORT_DEVICE_EXTENSION, *PMINIPORT_DEVICE_EXTENSION;

typedef struct _MINIPORT {
    struct _FDO_DEVICE_EXTENSION *DeviceExtension;
    PHW_INITIALIZATION_DATA InitData;
    PORT_CONFIGURATION_INFORMATION PortConfig;
    PMINIPORT_DEVICE_EXTENSION MiniportExtension;
} MINIPORT, *PMINIPORT;

typedef struct _UNIT_DATA {
    LIST_ENTRY ListEntry;
    INQUIRYDATA InquiryData;
} UNIT_DATA, *PUNIT_DATA;

typedef struct _FDO_DEVICE_EXTENSION {
    EXTENSION_TYPE ExtensionType; /* Must be first member */

    PDEVICE_OBJECT Device;
    PDEVICE_OBJECT LowerDevice;
    PDEVICE_OBJECT PhysicalDevice;
    PDRIVER_OBJECT_EXTENSION DriverExtension;
    DEVICE_STATE PnpState;
    LIST_ENTRY AdapterListEntry;
    MINIPORT Miniport;
    ULONG PortNumber;
    ULONG BusNumber;
    ULONG SlotNumber;
    PCM_RESOURCE_LIST AllocatedResources;
    PCM_RESOURCE_LIST TranslatedResources;
    PMAPPED_ADDRESS MappedAddressList;
    PVOID UncachedExtensionVirtualBase;
    PHYSICAL_ADDRESS UncachedExtensionPhysicalBase;
    ULONG UncachedExtensionSize;
    PHW_PASSIVE_INITIALIZE_ROUTINE HwPassiveInitRoutine;
    PKINTERRUPT Interrupt;
    ULONG InterruptIrql;
    PDMA_ADAPTER DmaAdapter;
    ULONG NumberOfMapRegisters;
    PVOID MapRegisterBase;

    LIST_ENTRY PdoListHead;
    ULONG PdoCount;
} FDO_DEVICE_EXTENSION, *PFDO_DEVICE_EXTENSION;

typedef struct _PDO_DEVICE_EXTENSION {
    EXTENSION_TYPE ExtensionType; /* Must be first member */

    PDEVICE_OBJECT Device;
    PFDO_DEVICE_EXTENSION FdoExtension;
    DEVICE_STATE PnpState;
    LIST_ENTRY PdoListEntry;

    ULONG Bus;
    ULONG Target;
    ULONG Lun;
    PINQUIRYDATA InquiryBuffer;
    KEVENT QueueUnfrozen;
    BOOLEAN DeviceClaimed;
    BOOLEAN QueueFrozen;
} PDO_DEVICE_EXTENSION, *PPDO_DEVICE_EXTENSION;

typedef struct _SRB_PORT_CONTEXT {
    volatile LONG CompletionQueued;
    IO_WORKITEM CompletionWorkItem;
    PSTORAGE_REQUEST_BLOCK Srb;
    PMDL Mdl;
    PSCATTER_GATHER_LIST SgList;
    PIRP Irp;
    PDMA_ADAPTER DmaAdapter;
    BOOLEAN DeallocateMdl;
    BOOLEAN WriteToDevice;
} SRB_PORT_CONTEXT, *PSRB_PORT_CONTEXT;

/* fdo.c */

NTSTATUS PortFdoScsi(IN PDEVICE_OBJECT DeviceObject,
		     IN PIRP Irp);

NTSTATUS PortFdoDeviceControl(IN PDEVICE_OBJECT DeviceObject,
			      IN PIRP Irp);

NTSTATUS PortFdoPnp(IN PDEVICE_OBJECT DeviceObject,
		    IN PIRP Irp);

NTSTATUS PortFdoInitDma(IN PFDO_DEVICE_EXTENSION FdoExt,
			IN PPORT_CONFIGURATION_INFORMATION PortConfig);

/* miniport.c */

NTSTATUS MiniportInitialize(IN PMINIPORT Miniport,
			    IN PFDO_DEVICE_EXTENSION DeviceExtension,
			    IN PHW_INITIALIZATION_DATA HwInitializationData);

NTSTATUS MiniportFindAdapter(IN PMINIPORT Miniport);

NTSTATUS MiniportHwInitialize(IN PMINIPORT Miniport);

BOOLEAN MiniportHwInterrupt(IN PMINIPORT Miniport);

BOOLEAN MiniportBuildIo(IN PMINIPORT Miniport,
			IN PSTORAGE_REQUEST_BLOCK Srb);

BOOLEAN MiniportStartIo(IN PMINIPORT Miniport,
			IN PSTORAGE_REQUEST_BLOCK Srb);

/* misc.c */

NTAPI NTSTATUS ForwardIrpAndForget(IN PDEVICE_OBJECT LowerDevice,
				   IN PIRP Irp);

INTERFACE_TYPE GetBusInterface(PDEVICE_OBJECT DeviceObject);

PCM_RESOURCE_LIST CopyResourceList(PCM_RESOURCE_LIST Source);

BOOLEAN TranslateResourceListAddress(PFDO_DEVICE_EXTENSION DeviceExtension,
				     INTERFACE_TYPE BusType,
				     ULONG SystemIoBusNumber,
				     STOR_PHYSICAL_ADDRESS IoAddress,
				     ULONG NumberOfBytes,
				     BOOLEAN InIoSpace,
				     PPHYSICAL_ADDRESS TranslatedAddress);

NTSTATUS GetResourceListInterrupt(PFDO_DEVICE_EXTENSION DeviceExtension,
				  PULONG Vector,
				  PKIRQL Irql,
				  KINTERRUPT_MODE *InterruptMode,
				  PBOOLEAN ShareVector,
				  PKAFFINITY Affinity);

NTSTATUS AllocateAddressMapping(PMAPPED_ADDRESS *MappedAddressList,
				STOR_PHYSICAL_ADDRESS IoAddress,
				PVOID MappedAddress,
				ULONG NumberOfBytes,
				ULONG BusNumber);

/* pdo.c */

NTSTATUS PortCreatePdo(IN PFDO_DEVICE_EXTENSION FdoExtension,
		       IN ULONG Bus,
		       IN ULONG Target,
		       IN ULONG Lun,
		       OUT PPDO_DEVICE_EXTENSION *PdoExtension);

NTSTATUS PortDeletePdo(IN PPDO_DEVICE_EXTENSION PdoExtension);

VOID PortPdoSetBusy(IN PPDO_DEVICE_EXTENSION PdoExt);

VOID PortPdoSetReady(IN PPDO_DEVICE_EXTENSION PdoExt);

VOID PortCompleteRequest(IN PSTORAGE_REQUEST_BLOCK Srb,
			 IN BOOLEAN Defer);

NTSTATUS PortPdoScsi(IN PDEVICE_OBJECT DeviceObject,
		     IN PIRP Irp);

NTSTATUS PortPdoDeviceControl(IN PDEVICE_OBJECT DeviceObject,
			      IN PIRP Irp);

NTSTATUS PortPdoPnp(IN PDEVICE_OBJECT DeviceObject,
		    IN PIRP Irp);


/* storport.c */

PHW_INITIALIZATION_DATA PortGetDriverInitData(PDRIVER_OBJECT_EXTENSION DriverExtension,
					      INTERFACE_TYPE InterfaceType);

NTAPI NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject,
			   IN PUNICODE_STRING RegistryPath);

#endif /* _STORPORT_PCH_ */
