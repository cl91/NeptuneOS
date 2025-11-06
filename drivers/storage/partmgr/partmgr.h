/*
 * PROJECT:     Partition manager driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Main header
 * COPYRIGHT:   2020 Victor Perevertkin (victor.perevertkin@reactos.org)
 */

#ifndef _PARTMGR_H_
#define _PARTMGR_H_

#include <ntifs.h>
#include <mountdev.h>
#include <ntddvol.h>
#include <ntdddisk.h>
#include <ioevent.h>
#include <stdio.h>

#define TAG_PARTMGR 'MtrP'

#define ERR(fmt, ...) ERR__(DPFLTR_DISK_ID, fmt, ##__VA_ARGS__)
#define WARN(fmt, ...) WARN__(DPFLTR_DISK_ID, fmt, ##__VA_ARGS__)
#define TRACE(fmt, ...) TRACE__(DPFLTR_DISK_ID, fmt, ##__VA_ARGS__)
#define INFO(fmt, ...) INFO__(DPFLTR_DISK_ID, fmt, ##__VA_ARGS__)

// from disk.sys
typedef struct _DISK_GEOMETRY_EX_INTERNAL {
    DISK_GEOMETRY Geometry;
    INT64 DiskSize;
    DISK_PARTITION_INFO Partition;
    DISK_DETECTION_INFO Detection;
} DISK_GEOMETRY_EX_INTERNAL, *PDISK_GEOMETRY_EX_INTERNAL;

// Unique ID data for basic (disk partition-based) volumes.
// It is stored in the MOUNTDEV_UNIQUE_ID::UniqueId member
// as an array of bytes.
#include <pshpack1.h>
typedef union _BASIC_VOLUME_UNIQUE_ID {
    struct {
	ULONG Signature;
	ULONGLONG StartingOffset;
    } Mbr;
    struct {
	ULONGLONG Signature; // UCHAR[8] // "DMIO:ID:"
	GUID PartitionGuid;
    } Gpt;
} BASIC_VOLUME_UNIQUE_ID, *PBASIC_VOLUME_UNIQUE_ID;
#include <poppack.h>
C_ASSERT(RTL_FIELD_SIZE(BASIC_VOLUME_UNIQUE_ID, Mbr) == 0x0C);
C_ASSERT(RTL_FIELD_SIZE(BASIC_VOLUME_UNIQUE_ID, Gpt) == 0x18);

#define DMIO_ID_SIGNATURE (*(ULONGLONG *)"DMIO:ID:")

typedef struct _FDO_EXTENSION {
    BOOLEAN IsFDO;
    PDEVICE_OBJECT DeviceObject;
    PDEVICE_OBJECT LowerDevice;
    PDEVICE_OBJECT PhysicalDiskDO;
    KEVENT SyncEvent;

    BOOLEAN LayoutValid;
    PDRIVE_LAYOUT_INFORMATION_EX LayoutCache;

    SINGLE_LIST_ENTRY PartitionList;
    UINT32 EnumeratedPartitionsTotal;
    BOOLEAN IsSuperFloppy;

    struct {
	UINT64 DiskSize;
	UINT32 DeviceNumber;
	UINT32 BytesPerSector;
	PARTITION_STYLE PartitionStyle;
	union {
	    struct {
		UINT32 Signature;
	    } Mbr;
	    struct {
		GUID DiskId;
	    } Gpt;
	};
    } DiskData;
    UNICODE_STRING DiskInterfaceName;
} FDO_EXTENSION, *PFDO_EXTENSION;

typedef struct _PARTITION_EXTENSION {
    BOOLEAN IsFDO;
    PDEVICE_OBJECT DeviceObject;
    PDEVICE_OBJECT LowerDevice;
    PDEVICE_OBJECT Part0Device;

    UINT64 StartingOffset;
    UINT64 PartitionLength;
    SINGLE_LIST_ENTRY ListEntry;

    UINT32 VolumeNumber; // Volume number in the "\Device\HarddiskVolumeN" device name
    UINT32 DetectedNumber;
    UINT32 OnDiskNumber; // partition number for issuing Io requests to the kernel
    BOOLEAN IsEnumerated; // reported via IRP_MN_QUERY_DEVICE_RELATIONS
    BOOLEAN SymlinkCreated;
    BOOLEAN Attached; // attached to PartitionList of the FDO
    union {
	struct {
	    GUID PartitionType;
	    GUID PartitionId;
	    UINT64 Attributes;
	    WCHAR Name[36];
	} Gpt;
	struct {
	    UINT8 PartitionType;
	    BOOLEAN BootIndicator;
	    BOOLEAN RecognizedPartition;
	    UINT32 HiddenSectors;
	} Mbr;
    };
    UNICODE_STRING PartitionInterfaceName;
    UNICODE_STRING VolumeInterfaceName;
    UNICODE_STRING DeviceName;
} PARTITION_EXTENSION, *PPARTITION_EXTENSION;

NTSTATUS PartitionCreateDevice(IN PDEVICE_OBJECT FDObject,
			       IN PPARTITION_INFORMATION_EX PartitionEntry,
			       IN UINT32 OnDiskNumber,
			       IN PARTITION_STYLE PartitionStyle,
			       OUT PDEVICE_OBJECT *PDO);

NTSTATUS PartitionHandleRemove(IN PPARTITION_EXTENSION PartExt,
			       IN BOOLEAN FinalRemove);

NTSTATUS PartitionHandlePnp(IN PDEVICE_OBJECT DeviceObject,
			    IN PIRP Irp);

NTSTATUS PartitionHandleDeviceControl(IN PDEVICE_OBJECT DeviceObject,
				      IN PIRP Irp);

NTAPI NTSTATUS ForwardIrpAndForget(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

NTSTATUS IssueSyncIoControlRequest(IN UINT32 IoControlCode,
				   IN PDEVICE_OBJECT DeviceObject,
				   IN PVOID InputBuffer,
				   IN ULONG InputBufferLength,
				   IN PVOID OutputBuffer,
				   IN ULONG OutputBufferLength,
				   IN BOOLEAN InternalDeviceIoControl);

FORCEINLINE BOOLEAN VerifyIrpOutBufferSize(IN PIRP Irp, IN SIZE_T Size)
{
    PIO_STACK_LOCATION ioStack = IoGetCurrentIrpStackLocation(Irp);
    if (ioStack->Parameters.DeviceIoControl.OutputBufferLength < Size) {
	Irp->IoStatus.Information = Size;
	return FALSE;
    }
    return TRUE;
}

FORCEINLINE BOOLEAN VerifyIrpInBufferSize(IN PIRP Irp, IN SIZE_T Size)
{
    PIO_STACK_LOCATION ioStack = IoGetCurrentIrpStackLocation(Irp);
    if (ioStack->Parameters.DeviceIoControl.InputBufferLength < Size) {
	Irp->IoStatus.Information = Size;
	return FALSE;
    }
    return TRUE;
}

FORCEINLINE VOID PartMgrAcquireLayoutLock(IN PFDO_EXTENSION FdoExtension)
{
    PAGED_CODE();

    KeWaitForSingleObject(&FdoExtension->SyncEvent, Executive, KernelMode, FALSE, NULL);
}

FORCEINLINE VOID PartMgrReleaseLayoutLock(IN PFDO_EXTENSION FdoExtension)
{
    PAGED_CODE();

    KeSetEvent(&FdoExtension->SyncEvent);
}

FORCEINLINE PCSTR GetIRPMinorFunctionString(UCHAR MinorFunction)
{
    switch (MinorFunction) {
    case IRP_MN_START_DEVICE:
	return "IRP_MN_START_DEVICE";
    case IRP_MN_QUERY_REMOVE_DEVICE:
	return "IRP_MN_QUERY_REMOVE_DEVICE";
    case IRP_MN_REMOVE_DEVICE:
	return "IRP_MN_REMOVE_DEVICE";
    case IRP_MN_CANCEL_REMOVE_DEVICE:
	return "IRP_MN_CANCEL_REMOVE_DEVICE";
    case IRP_MN_STOP_DEVICE:
	return "IRP_MN_STOP_DEVICE";
    case IRP_MN_QUERY_STOP_DEVICE:
	return "IRP_MN_QUERY_STOP_DEVICE";
    case IRP_MN_CANCEL_STOP_DEVICE:
	return "IRP_MN_CANCEL_STOP_DEVICE";
    case IRP_MN_QUERY_DEVICE_RELATIONS:
	return "IRP_MN_QUERY_DEVICE_RELATIONS";
    case IRP_MN_QUERY_INTERFACE:
	return "IRP_MN_QUERY_INTERFACE";
    case IRP_MN_QUERY_CAPABILITIES:
	return "IRP_MN_QUERY_CAPABILITIES";
    case IRP_MN_QUERY_RESOURCES:
	return "IRP_MN_QUERY_RESOURCES";
    case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:
	return "IRP_MN_QUERY_RESOURCE_REQUIREMENTS";
    case IRP_MN_QUERY_DEVICE_TEXT:
	return "IRP_MN_QUERY_DEVICE_TEXT";
    case IRP_MN_FILTER_RESOURCE_REQUIREMENTS:
	return "IRP_MN_FILTER_RESOURCE_REQUIREMENTS";
    case IRP_MN_READ_CONFIG:
	return "IRP_MN_READ_CONFIG";
    case IRP_MN_WRITE_CONFIG:
	return "IRP_MN_WRITE_CONFIG";
    case IRP_MN_EJECT:
	return "IRP_MN_EJECT";
    case IRP_MN_SET_LOCK:
	return "IRP_MN_SET_LOCK";
    case IRP_MN_QUERY_ID:
	return "IRP_MN_QUERY_ID";
    case IRP_MN_QUERY_PNP_DEVICE_STATE:
	return "IRP_MN_QUERY_PNP_DEVICE_STATE";
    case IRP_MN_QUERY_BUS_INFORMATION:
	return "IRP_MN_QUERY_BUS_INFORMATION";
    case IRP_MN_DEVICE_USAGE_NOTIFICATION:
	return "IRP_MN_DEVICE_USAGE_NOTIFICATION";
    case IRP_MN_SURPRISE_REMOVAL:
	return "IRP_MN_SURPRISE_REMOVAL";
    default:
	return "(unknown)IRP_MN";
    }
}

FORCEINLINE PCSTR DbgGetDeviceRelationString(DEVICE_RELATION_TYPE Type)
{
    switch (Type) {
    case BusRelations:
	return "BusRelations";
    case EjectionRelations:
	return "EjectionRelations";
    case RemovalRelations:
	return "RemovalRelations";
    case TargetDeviceRelation:
	return "TargetDeviceRelation";
    default:
	return "(unknown)Relation";
    }
}

FORCEINLINE PCSTR DbgGetDeviceIDString(BUS_QUERY_ID_TYPE Type)
{
    switch (Type) {
    case BusQueryDeviceID:
	return "BusQueryDeviceID";
    case BusQueryHardwareIDs:
	return "BusQueryHardwareIDs";
    case BusQueryCompatibleIDs:
	return "BusQueryCompatibleIDs";
    case BusQueryInstanceID:
	return "BusQueryInstanceID";
    case BusQueryDeviceSerialNumber:
	return "BusQueryDeviceSerialNumber";
    default:
	return "(unknown)QueryID";
    }
}

#endif // _PARTMGR_H_
