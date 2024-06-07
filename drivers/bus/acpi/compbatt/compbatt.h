/*
 * PROJECT:         ReactOS Composite Battery Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            boot/drivers/bus/acpi/compbatt/compbatt.h
 * PURPOSE:         Main Header File
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

#ifndef _COMPBATT_PCH_
#define _COMPBATT_PCH_

#include <ntddk.h>
#include <batclass.h>
#include <debug.h>

#define COMPBATT_BATTERY_INFORMATION_PRESENT 0x04
#define COMPBATT_TAG_ASSIGNED 0x80

typedef struct _COMPBATT_BATTERY_DATA {
    LIST_ENTRY BatteryLink;
    PDEVICE_OBJECT DeviceObject;
    PIRP Irp;
    BOOLEAN WaitFlag;
    BATTERY_WAIT_STATUS WaitStatus;
    ULONG Tag;
    ULONG Flags;
    BATTERY_INFORMATION BatteryInformation;
    BATTERY_STATUS BatteryStatus;
    ULONGLONG InterruptTime;
    UNICODE_STRING BatteryName;
} COMPBATT_BATTERY_DATA, *PCOMPBATT_BATTERY_DATA;

typedef struct _COMPBATT_DEVICE_EXTENSION {
    PVOID ClassData;
    ULONG NextTag;
    LIST_ENTRY BatteryList;
    ULONG Tag;
    ULONG Flags;
    BATTERY_INFORMATION BatteryInformation;
    BATTERY_STATUS BatteryStatus;
    ULONGLONG InterruptTime;
    POWER_STATE PowerState;
    ULONG LowCapacity;
    ULONG HighCapacity;
    PDEVICE_OBJECT AttachedDevice;
    PDEVICE_OBJECT DeviceObject;
    PVOID NotificationEntry;
} COMPBATT_DEVICE_EXTENSION, *PCOMPBATT_DEVICE_EXTENSION;

NTAPI NTSTATUS CompBattAddDevice(IN PDRIVER_OBJECT DriverObject,
				 IN PDEVICE_OBJECT PdoDeviceObject);

NTAPI NTSTATUS CompBattPowerDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

NTAPI NTSTATUS CompBattPnpDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

NTAPI NTSTATUS CompBattQueryInformation(IN PCOMPBATT_DEVICE_EXTENSION FdoExtension,
					IN ULONG Tag,
					IN BATTERY_QUERY_INFORMATION_LEVEL InfoLevel,
					IN OPTIONAL LONG AtRate, IN PVOID Buffer,
					IN ULONG BufferLength, OUT PULONG ReturnedLength);

NTAPI NTSTATUS CompBattQueryStatus(IN PCOMPBATT_DEVICE_EXTENSION DeviceExtension,
				   IN ULONG Tag, IN PBATTERY_STATUS BatteryStatus);

NTAPI NTSTATUS CompBattSetStatusNotify(IN PCOMPBATT_DEVICE_EXTENSION DeviceExtension,
				       IN ULONG BatteryTag,
				       IN PBATTERY_NOTIFY BatteryNotify);

NTAPI NTSTATUS CompBattDisableStatusNotify(IN PCOMPBATT_DEVICE_EXTENSION DeviceExtension);

NTAPI NTSTATUS CompBattQueryTag(IN PCOMPBATT_DEVICE_EXTENSION DeviceExtension,
				OUT PULONG Tag);

extern ULONG CompBattDebug;

#endif /* _COMPBATT_PCH_ */
