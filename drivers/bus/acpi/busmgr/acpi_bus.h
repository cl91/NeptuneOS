/*
 *  acpi_bus.h - ACPI Bus Driver ($Revision: 22 $)
 *
 *  Copyright (C) 2001, 2002 Andy Grover <andrew.grover@intel.com>
 *  Copyright (C) 2001, 2002 Paul Diefenbaugh <paul.s.diefenbaugh@intel.com>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or (at
 *  your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#ifndef __ACPI_BUS_H__
#define __ACPI_BUS_H__

#include <acpi.h>

/* TBD: Make dynamic */
#define ACPI_MAX_HANDLES 10
typedef struct _ACPI_HANDLE_LIST {
    UINT32 Count;
    ACPI_HANDLE Handles[ACPI_MAX_HANDLES];
} ACPI_HANDLE_LIST, *PACPI_HANDLE_LIST;

typedef enum _ACPI_BUS_REMOVAL_TYPE {
    ACPI_BUS_REMOVAL_NORMAL = 0,
    ACPI_BUS_REMOVAL_EJECT,
    ACPI_BUS_REMOVAL_SUPRISE,
    ACPI_BUS_REMOVAL_TYPE_COUNT
} ACPI_BUS_REMOVAL_TYPE;

typedef enum _ACPI_BUS_DEVICE_TYPE {
    ACPI_BUS_TYPE_DEVICE = 0,
    ACPI_BUS_TYPE_POWER,
    ACPI_BUS_TYPE_PROCESSOR,
    ACPI_BUS_TYPE_THERMAL,
    ACPI_BUS_TYPE_SYSTEM,
    ACPI_BUS_TYPE_POWER_BUTTON,
    ACPI_BUS_TYPE_SLEEP_BUTTON,
    ACPI_BUS_TYPE_POWER_BUTTONF,
    ACPI_BUS_TYPE_SLEEP_BUTTONF,
    ACPI_BUS_DEVICE_TYPE_COUNT
} ACPI_BUS_DEVICE_TYPE;

struct _ACPI_BUSMGR_COMPONENT;
struct _ACPI_DEVICE;

/*
 * ACPI Driver
 * -----------
 */

typedef ACPI_STATUS (*ACPI_OP_ADD)(IN PDEVICE_OBJECT DeviceObject,
				   struct _ACPI_DEVICE *Device);
typedef ACPI_STATUS (*ACPI_OP_REMOVE)(struct _ACPI_DEVICE *Device, ACPI_BUS_REMOVAL_TYPE Type);
typedef ACPI_STATUS (*ACPI_OP_START)(struct _ACPI_DEVICE *Device);
typedef ACPI_STATUS (*ACPI_OP_SUSPEND)(struct _ACPI_DEVICE *Device, INT State);
typedef ACPI_STATUS (*ACPI_OP_RESUME)(struct _ACPI_DEVICE *Device, INT State);
typedef ACPI_STATUS (*ACPI_OP_SCAN)(struct _ACPI_DEVICE *Device);
typedef ACPI_STATUS (*ACPI_OP_BIND)(struct _ACPI_DEVICE *Device);
typedef ACPI_STATUS (*ACPI_OP_UNBIND)(struct _ACPI_DEVICE *Device);
typedef VOID (*ACPI_OP_NOTIFY)(struct _ACPI_DEVICE *Device, UINT32 Event);

typedef struct _ACPI_DEVICE_OPS {
    ACPI_OP_ADD Add;
    ACPI_OP_REMOVE Remove;
    ACPI_OP_START Start;
    ACPI_OP_SUSPEND Suspend;
    ACPI_OP_RESUME Resume;
    ACPI_OP_BIND Bind;
    ACPI_OP_UNBIND Unbind;
    ACPI_OP_NOTIFY Notify;
    ACPI_OP_SCAN Scan;
} ACPI_DEVICE_OPS, *PACPI_DEVICE_OPS;

#define ACPI_BUSMGR_COMPONENT_ALL_NOTIFY_EVENTS 0x1 /* system AND device events */

typedef struct _ACPI_BUSMGR_COMPONENT {
    LIST_ENTRY Node;
    CHAR Name[80];
    CHAR Class[80];
    INT References;
    ULONG Flags;
    PCHAR Ids; /* Supported Hardware IDs */
    ACPI_DEVICE_OPS Ops;
} ACPI_BUSMGR_COMPONENT, *PACPI_BUSMGR_COMPONENT;

/*
 * ACPI Device
 * -----------
 */

/* Status (_STA) */

typedef struct _ACPI_DEVICE_STATUS {
    UINT32 Present : 1;
    UINT32 Enabled : 1;
    UINT32 ShowInUi : 1;
    UINT32 Functional : 1;
    UINT32 BatteryPresent : 1;
    UINT32 Reserved : 27;
} ACPI_DEVICE_STATUS, *PACPI_DEVICE_STATUS;

/* Flags */

typedef struct _ACPI_DEVICE_FLAGS {
    UINT32 DynamicStatus : 1;
    UINT32 HardwareId : 1;
    UINT32 CompatibleIds : 1;
    UINT32 BusAddress : 1;
    UINT32 UniqueId : 1;
    UINT32 Removable : 1;
    UINT32 Ejectable : 1;
    UINT32 Lockable : 1;
    UINT32 SurpriseRemovalOk : 1;
    UINT32 PowerManageable : 1;
    UINT32 PerformanceManageable : 1;
    UINT32 WakeCapable : 1;
    UINT32 ForcePowerState : 1;
    UINT32 Reserved : 20;
} ACPI_DEVICE_FLAGS;

/* Plug and Play */

typedef CHAR ACPI_BUS_ID[8];
typedef ULONG64 ACPI_BUS_ADDRESS;
typedef PCHAR ACPI_HARDWARE_ID;
typedef CHAR ACPI_UNIQUE_ID[9];
typedef CHAR ACPI_DEVICE_NAME[40];
typedef CHAR ACPI_DEVICE_CLASS[20];

typedef struct _ACPI_DEVICE_PNP {
    ACPI_BUS_ID BusId; /* Object name */
    ACPI_BUS_ADDRESS BusAddress; /* _ADR */
    ACPI_HARDWARE_ID HardwareId; /* _HID */
    ACPI_PNP_DEVICE_ID_LIST *CidList; /* _CIDs */
    ACPI_UNIQUE_ID UniqueId; /* _UID */
    ACPI_DEVICE_NAME DeviceName; /* Driver-determined */
    ACPI_DEVICE_CLASS DeviceClass; /*        "          */
} ACPI_DEVICE_PNP;

#define ACPI_DEVICE_BID(d) ((d)->Pnp.BusId)
#define ACPI_DEVICE_ADR(d) ((d)->Pnp.BusAddress)
#define ACPI_DEVICE_HID(d) ((d)->Pnp.HardwareId)
#define ACPI_DEVICE_UID(d) ((d)->Pnp.UniqueId)
#define ACPI_DEVICE_NAME(d) ((d)->Pnp.DeviceName)
#define ACPI_DEVICE_CLASS(d) ((d)->Pnp.DeviceClass)

/* Power Management */

typedef struct _ACPI_DEVICE_POWER_FLAGS {
    UINT32 ExplicitGet : 1; /* _PSC present? */
    UINT32 PowerResources : 1; /* Power resources */
    UINT32 InrushCurrent : 1; /* Serialize Dx->D0 */
    UINT32 PowerRemoved : 1; /* Optimize Dx->D0 */
    UINT32 Reserved : 28;
} ACPI_DEVICE_POWER_FLAGS;

typedef struct _ACPI_DEVICE_POWER_STATE {
    struct {
	UINT8 Valid : 1;
	UINT8 ExplicitSet : 1; /* _PSx present? */
	UINT8 Reserved : 6;
    } Flags;
    INT Power; /* % Power (compared to D0) */
    INT Latency; /* Dx->D0 time (microseconds) */
    ACPI_HANDLE_LIST Resources; /* Power resources referenced */
} ACPI_DEVICE_POWER_STATE, *PACPI_DEVICE_POWER_STATE;

typedef struct _ACPI_DEVICE_POWER {
    INT State; /* Current state */
    ACPI_DEVICE_POWER_FLAGS Flags;
    ACPI_DEVICE_POWER_STATE States[4]; /* Power states (D0-D3) */
} ACPI_DEVICE_POWER;

/* Performance Management */

typedef struct _ACPI_DEVICE_PERF_FLAGS {
    UINT8 Reserved : 8;
} ACPI_DEVICE_PERF_FLAGS;

typedef struct _ACPI_DEVICE_PERF_STATE {
    struct {
	UINT8 Valid : 1;
	UINT8 Reserved : 7;
    } Flags;
    UINT8 Power; /* % Power (compared to P0) */
    UINT8 Performance; /* % Performance (    "   ) */
    INT Latency; /* Px->P0 time (microseconds) */
} ACPI_DEVICE_PERF_STATE, *PACPI_DEVICE_PERF_STATE;

typedef struct _ACPI_DEVICE_PERF {
    INT State;
    ACPI_DEVICE_PERF_FLAGS Flags;
    INT StateCount;
    PACPI_DEVICE_PERF_STATE States;
} ACPI_DEVICE_PERF, *PACPI_DEVICE_PERF;

/* Wakeup Management */
typedef struct _ACPI_DEVICE_WAKEUP_FLAGS {
    UINT8 Valid : 1; /* Can successfully enable wakeup? */
    UINT8 RunWake : 1; /* Run-Wake GPE devices */
} ACPI_DEVICE_WAKEUP_FLAGS;

typedef struct _ACPI_DEVICE_WAKEUP_STATE {
    UINT8 Enabled : 1;
} ACPI_DEVICE_WAKEUP_STATE;

typedef struct _ACPI_DEVICE_WAKEUP {
    ACPI_HANDLE GpeDevice;
    ACPI_INTEGER GpeNumber;
    ACPI_INTEGER SleepState;
    ACPI_HANDLE_LIST Resources;
    ACPI_DEVICE_WAKEUP_STATE State;
    ACPI_DEVICE_WAKEUP_FLAGS Flags;
    INT PrepareCount;
} ACPI_DEVICE_WAKEUP, *PACPI_DEVICE_WAKEUP;

/* Device */

typedef struct _ACPI_DEVICE {
    INT DeviceType;
    ACPI_HANDLE Handle;
    struct _ACPI_DEVICE *Parent;
    LIST_ENTRY Children;
    LIST_ENTRY Node;
    LIST_ENTRY WakeupList;
    ACPI_DEVICE_STATUS Status;
    ACPI_DEVICE_FLAGS Flags;
    ACPI_DEVICE_PNP Pnp;
    ACPI_DEVICE_POWER Power;
    ACPI_DEVICE_WAKEUP Wakeup;
    ACPI_DEVICE_PERF Performance;
    ACPI_DEVICE_OPS Ops;
    PACPI_BUSMGR_COMPONENT Driver;
    PVOID DriverData;
    ACPI_BUS_REMOVAL_TYPE RemovalType; /* indicate for different removal type */
} ACPI_DEVICE, *PACPI_DEVICE;

#define ACPI_BUSMGR_COMPONENT_DATA(d) ((d)->DriverData)

#define TO_ACPI_DEVICE(d) container_of(d, ACPI_DEVICE, dev)
#define TO_ACPI_BUSMGR_COMPONENT(d) container_of(d, ACPI_BUSMGR_COMPONENT, drv)

/* bus.c */
INT AcpiBusGetPower(ACPI_HANDLE Handle, INT *State);
INT AcpiBusGenerateEvent(PACPI_DEVICE Device, UINT8 Type, INT Data);
INT AcpiBusRegisterDriver(IN PDEVICE_OBJECT BusFdo,
			  PACPI_BUSMGR_COMPONENT Driver);
VOID AcpiBusUnregisterDriver(IN PDEVICE_OBJECT BusFdo,
			     PACPI_BUSMGR_COMPONENT Driver);
INT AcpiBusGetDevice(ACPI_HANDLE Handle, PACPI_DEVICE *Device);

/* button.c */
INT AcpiButtonInit(IN PDEVICE_OBJECT BusFdo);
VOID AcpiButtonExit(IN PDEVICE_OBJECT BusFdo);

/* ec.c */
VOID AcpiEcProbeEcdt(IN PDEVICE_OBJECT BusFdo);
VOID AcpiEcProbeDsdt(IN PDEVICE_OBJECT BusFdo);
VOID AcpiEcInit(IN PDEVICE_OBJECT BusFdo);
ACPI_STATUS EcRead(UCHAR Addr, PUCHAR Data);
ACPI_STATUS EcWrite(UCHAR Addr, UCHAR Val);

/* hwhacks.c */
ACPI_STATUS AcpiApplyStartDeviceHacks(IN PACPI_DEVICE Device);

/* power.c */
INT AcpiPowerGetInferredState(PACPI_DEVICE Device);
INT AcpiPowerTransition(PACPI_DEVICE Device, INT State);
INT AcpiPowerInit(IN PDEVICE_OBJECT BusFdo);

/* utils.c */
ACPI_STATUS AcpiEvaluateInteger(ACPI_HANDLE Handle,
				ACPI_STRING Pathname,
				struct acpi_object_list *Arguments,
				ULONG64 *Data);
ACPI_STATUS AcpiEvaluateReference(ACPI_HANDLE Handle,
				  ACPI_STRING Pathname,
				  struct acpi_object_list *Arguments,
				  PACPI_HANDLE_LIST List);

#endif /*__ACPI_BUS_H__*/
