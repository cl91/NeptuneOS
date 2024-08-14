#pragma once

#include <initguid.h>
#include <ntddk.h>
#include <acpi.h>
#include <accommon.h>

#include <wdmguid.h>
#include <acpiioct.h>
#include <ntintsafe.h>

#define ACPI_TAG 'IPCA'

#define LIST_HEAD_INIT(name) { &(name), &(name) }
#define LIST_HEAD(name) LIST_ENTRY name = LIST_HEAD_INIT(name)

#define LoopOverList(Entry, ListHead, Type, Field)			\
    for (Type *Entry = CONTAINING_RECORD((ListHead)->Flink, Type, Field), \
	     *__LoopOverList_flink = CONTAINING_RECORD((Entry)->Field.Flink, Type, Field); \
	 &(Entry)->Field != (ListHead); Entry = __LoopOverList_flink,	\
	     __LoopOverList_flink = CONTAINING_RECORD((__LoopOverList_flink)->Field.Flink, Type, Field))

extern UNICODE_STRING ProcessorHardwareIds;
extern LPWSTR ProcessorIdString;
extern LPWSTR ProcessorNameString;

typedef enum _DEVICE_PNP_STATE {
    NotStarted = 0, // Not started yet
    Started, // Device has received the START_DEVICE IRP
    StopPending, // Device has received the QUERY_STOP IRP
    Stopped, // Device has received the STOP_DEVICE IRP
    RemovalPending, // Device has received the QUERY_REMOVE IRP
    UnKnown // Unknown state
} DEVICE_PNP_STATE;

//
// A common header for the device extensions of the PDOs and FDO
//
typedef struct _COMMON_DEVICE_DATA {
    PDEVICE_OBJECT Self;
    BOOLEAN IsFDO;
    DEVICE_PNP_STATE DevicePnPState;
    DEVICE_PNP_STATE PreviousPnPState;
    SYSTEM_POWER_STATE SystemPowerState;
    DEVICE_POWER_STATE DevicePowerState;
} COMMON_DEVICE_DATA, *PCOMMON_DEVICE_DATA;

typedef struct _PDO_DEVICE_DATA {
    COMMON_DEVICE_DATA Common;
    ACPI_HANDLE AcpiHandle;
    // A back pointer to the bus
    PDEVICE_OBJECT ParentFdo;
    // An array of (zero terminated wide character strings).
    // The array itself also null terminated
    PWCHAR HardwareIDs;
    // Link point to hold all the PDOs for a single bus together
    LIST_ENTRY Link;
    UNICODE_STRING InterfaceName;
} PDO_DEVICE_DATA, *PPDO_DEVICE_DATA;

//
// The device extension of the bus itself.  From whence the PDO's are born.
//
typedef struct _FDO_DEVICE_DATA {
    COMMON_DEVICE_DATA Common;
    PDEVICE_OBJECT UnderlyingPDO;

    // The underlying bus PDO and the actual device object to which our
    // FDO is attached
    PDEVICE_OBJECT NextLowerDriver;

    // List of PDOs created so far
    LIST_ENTRY ListOfPDOs;

    // The PDOs currently enumerated.
    ULONG NumPDOs;
} FDO_DEVICE_DATA, *PFDO_DEVICE_DATA;

#define FDO_FROM_PDO(pdoData) ((PFDO_DEVICE_DATA)(pdoData)->ParentFdo->DeviceExtension)

#define INITIALIZE_PNP_STATE(_Data_)		\
    (_Data_).DevicePnPState = NotStarted;	\
    (_Data_).PreviousPnPState = NotStarted;

#define SET_NEW_PNP_STATE(_Data_, _state_)			\
    (_Data_).PreviousPnPState = (_Data_).DevicePnPState;	\
    (_Data_).DevicePnPState = (_state_);

#define RESTORE_PREVIOUS_PNP_STATE(_Data_)			\
    (_Data_).DevicePnPState = (_Data_).PreviousPnPState;

/* eval.c */
NTSTATUS Bus_PDO_EvalMethod(IN PPDO_DEVICE_DATA DeviceData, IN OUT PIRP Irp);

/* osl.c */
VOID AcpiOsSetBusFdo(IN PDEVICE_OBJECT Fdo);
PDEVICE_OBJECT AcpiOsGetBusFdo();
VOID AcpiOsSetRootSystemTable(ACPI_PHYSICAL_ADDRESS Rsdt,
			      ULONG Length);
ULONG64 OslGetPciConfigurationAddress(ACPI_PCI_ID *PciId);

/* pnp.c */
#if DBG
PCHAR DbgDeviceRelationString(DEVICE_RELATION_TYPE Type);
#else
#define DbgDeviceRelationString(Type) ""
#endif
NTAPI NTSTATUS Bus_PnP(PDEVICE_OBJECT DeviceObject, PIRP Irp);

/* power.c */
NTAPI NTSTATUS Bus_Power(PDEVICE_OBJECT DeviceObject, PIRP Irp);

/* busmgr/bus.c */
int AcpiBusInitializeManager();
VOID AcpiBusTerminateManager();
int AcpiBusSetPower(ACPI_HANDLE handle, int state);
BOOLEAN AcpiBusPowerManageable(ACPI_HANDLE handle);

/* busmgr/button.c */
VOID AcpiBusQueueGetButtonEventIrp(IN PIRP Irp);

/* busmgr/enum.c */
NTSTATUS Bus_EnumerateDevices(PFDO_DEVICE_DATA DeviceExtension);

/* busmgr/pdo.c */
NTSTATUS Bus_PDO_PnP(PDEVICE_OBJECT DeviceObject, PIRP Irp,
		     PIO_STACK_LOCATION IrpStack,
		     PPDO_DEVICE_DATA DeviceData);

/* busmgr/system.c */
ACPI_STATUS AcpiBusSuspendSystem(UINT32 state);

/* bugmgr/utils.c */
NTSTATUS AcpiCreateVolatileRegistryTables(void);
