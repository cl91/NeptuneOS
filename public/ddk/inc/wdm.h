#pragma once

#include <nt.h>

typedef ULONG DEVICE_TYPE;
typedef PVOID PDRIVER_OBJECT;
typedef PVOID PDEVICE_OBJECT;

typedef NTSTATUS (NTAPI DRIVER_INITIALIZE)(IN PDRIVER_OBJECT DriverObject,
					   IN PUNICODE_STRING RegistryPath);
typedef DRIVER_INITIALIZE *PDRIVER_INITIALIZE;

NTAPI NTSYSAPI NTSTATUS IoCreateDevice(IN PDRIVER_OBJECT DriverObject,
				       IN ULONG DeviceExtensionSize,
				       IN PUNICODE_STRING DeviceName OPTIONAL,
				       IN DEVICE_TYPE DeviceType,
				       IN ULONG DeviceCharacteristics,
				       IN BOOLEAN Exclusive,
				       OUT PDEVICE_OBJECT *DeviceObject);
