/*++

Copyright (C) Microsoft Corporation, 1991 - 1999

Module Name:

    geometry.c

Abstract:

    SCSI disk class driver - this module contains all the code for generating
    disk geometries.

Environment:

    kernel mode only

Notes:

Revision History:

--*/

#include "disk.h"
#include <hal.h>

#ifdef DEBUG_USE_WPP
#include "geometry.tmh"
#endif

#if defined(_M_IX86) || defined(_M_AMD64)

DISK_GEOMETRY_SOURCE DiskUpdateGeometry(IN PFUNCTIONAL_DEVICE_EXTENSION DeviceExtension);

NTSTATUS DiskUpdateRemovableGeometry(IN PFUNCTIONAL_DEVICE_EXTENSION FdoExtension);

VOID DiskScanBusDetectInfo(IN PDRIVER_OBJECT DriverObject, IN HANDLE BusKey);

NTSTATUS DiskSaveBusDetectInfo(IN PDRIVER_OBJECT DriverObject, IN HANDLE TargetKey,
			       IN ULONG DiskNumber);

NTSTATUS DiskSaveGeometryDetectInfo(IN PDRIVER_OBJECT DriverObject,
				    IN HANDLE HardwareKey);

NTSTATUS DiskGetPortGeometry(IN PFUNCTIONAL_DEVICE_EXTENSION FdoExtension,
			     OUT PDISK_GEOMETRY Geometry);

typedef struct _DISK_DETECT_INFO {
    BOOLEAN Initialized;
    ULONG Style;
    ULONG Signature;
    ULONG MbrCheckSum;
    PDEVICE_OBJECT Device;
    CM_INT13_DRIVE_PARAMETER DriveParameters;
} DISK_DETECT_INFO, *PDISK_DETECT_INFO;

//
// Information about the disk geometries collected and saved into the registry
// by NTDETECT.COM or the system firmware.
//

PDISK_DETECT_INFO DetectInfoList = NULL;
ULONG DetectInfoCount = 0;
LONG DetectInfoUsedCount = 0;

#define GET_STARTING_SECTOR(p)                                              \
    ((ULONG)(p->StartingSectorLsb0) + (ULONG)(p->StartingSectorLsb1 << 8) + \
     (ULONG)(p->StartingSectorMsb0 << 16) + (ULONG)(p->StartingSectorMsb1 << 24))

#define GET_ENDING_S_OF_CHS(p) ((UCHAR)(p->EndingCylinderLsb & 0x3F))

//
// Definitions from hal.h
//

//
// Boot record disk partition table entry structure format
//

typedef struct _PARTITION_DESCRIPTOR {
    UCHAR ActiveFlag;
    UCHAR StartingTrack;
    UCHAR StartingCylinderLsb;
    UCHAR StartingCylinderMsb;
    UCHAR PartitionType;
    UCHAR EndingTrack;
    UCHAR EndingCylinderLsb;
    UCHAR EndingCylinderMsb;
    UCHAR StartingSectorLsb0;
    UCHAR StartingSectorLsb1;
    UCHAR StartingSectorMsb0;
    UCHAR StartingSectorMsb1;
    UCHAR PartitionLengthLsb0;
    UCHAR PartitionLengthLsb1;
    UCHAR PartitionLengthMsb0;
    UCHAR PartitionLengthMsb1;

} PARTITION_DESCRIPTOR, *PPARTITION_DESCRIPTOR;

//
// Number of partition table entries
//

#define NUM_PARTITION_TABLE_ENTRIES 4

//
// Partition table record and boot signature offsets in 16-bit words
//

#define PARTITION_TABLE_OFFSET (0x1be / 2)
#define BOOT_SIGNATURE_OFFSET ((0x200 / 2) - 1)

//
// Boot record signature value
//

#define BOOT_RECORD_SIGNATURE (0xaa55)

/*++

Routine Description:

    This routine saves away the firmware information about the disks which has
    been saved in the registry.  It generates a list (DetectInfoList) which
    contains the disk geometries, signatures & checksums of all drives which
    were examined by NtDetect.  This list is later used to assign geometries
    to disks as they are initialized.

Arguments:

    DriverObject - the driver being initialized.  This is used to get to the
                   hardware database.

Return Value:

    status.

--*/
NTSTATUS DiskSaveDetectInfo(PDRIVER_OBJECT DriverObject)
{
    OBJECT_ATTRIBUTES objectAttributes = { 0 };
    HANDLE hardwareKey;

    UNICODE_STRING unicodeString;
    HANDLE busKey;

    NTSTATUS status;

    InitializeObjectAttributes(&objectAttributes, DriverObject->HardwareDatabase,
			       OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    //
    // Create the hardware base key.
    //

    status = NtOpenKey(&hardwareKey, KEY_READ, &objectAttributes);

    if (!NT_SUCCESS(status)) {
	TracePrint((TRACE_LEVEL_ERROR, TRACE_FLAG_GENERAL,
		    "DiskSaveDetectInfo: Cannot open hardware data. "
		    "Name: %wZ\n",
		    DriverObject->HardwareDatabase));
	return status;
    }

    status = DiskSaveGeometryDetectInfo(DriverObject, hardwareKey);

    if (!NT_SUCCESS(status)) {
	TracePrint((TRACE_LEVEL_ERROR, TRACE_FLAG_GENERAL,
		    "DiskSaveDetectInfo: Can't query configuration data "
		    "(%#08lx)\n",
		    status));
	NtClose(hardwareKey);
	return status;
    }

    //
    // Open EISA bus key.
    //

    RtlInitUnicodeString(&unicodeString, L"EisaAdapter");
    InitializeObjectAttributes(&objectAttributes, &unicodeString,
			       OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, hardwareKey,
			       NULL);

    status = NtOpenKey(&busKey, KEY_READ, &objectAttributes);

    if (NT_SUCCESS(status)) {
	TracePrint((TRACE_LEVEL_INFORMATION, TRACE_FLAG_GENERAL,
		    "DiskSaveDetectInfo: Opened EisaAdapter key\n"));
	DiskScanBusDetectInfo(DriverObject, busKey);
	NtClose(busKey);
    }

    //
    // Open MultiFunction bus key.
    //

    RtlInitUnicodeString(&unicodeString, L"MultifunctionAdapter");
    InitializeObjectAttributes(&objectAttributes, &unicodeString,
			       OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, hardwareKey,
			       NULL);

    status = NtOpenKey(&busKey, KEY_READ, &objectAttributes);

    if (NT_SUCCESS(status)) {
	TracePrint((TRACE_LEVEL_INFORMATION, TRACE_FLAG_GENERAL,
		    "DiskSaveDetectInfo: Opened MultifunctionAdapter key\n"));
	DiskScanBusDetectInfo(DriverObject, busKey);
	NtClose(busKey);
    }

    NtClose(hardwareKey);

    return STATUS_SUCCESS;
}

/*++

Routine Description:

    This routine will cleanup the data structure built by DiskSaveDetectInfo.

Arguments:

    DriverObject - a pointer to the kernel object for this driver.

Return Value:

    none

--*/
VOID DiskCleanupDetectInfo(IN PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    FREE_POOL(DetectInfoList);
    return;
}

NTSTATUS DiskSaveGeometryDetectInfo(IN PDRIVER_OBJECT DriverObject, IN HANDLE HardwareKey)
{
    UNICODE_STRING unicodeString;
    PKEY_VALUE_FULL_INFORMATION keyData;
    ULONG length;

    PCM_FULL_RESOURCE_DESCRIPTOR fullDescriptor;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR partialDescriptor;

    PCM_INT13_DRIVE_PARAMETER driveParameters;
    ULONG numberOfDrives;

    ULONG i;

    NTSTATUS status;

    UNREFERENCED_PARAMETER(DriverObject);

    //
    // Get disk BIOS geometry information.
    //

    RtlInitUnicodeString(&unicodeString, L"Configuration Data");

    keyData = ExAllocatePoolWithTag(VALUE_BUFFER_SIZE, DISK_TAG_UPDATE_GEOM);

    if (keyData == NULL) {
	TracePrint((TRACE_LEVEL_ERROR, TRACE_FLAG_GENERAL,
		    "DiskSaveGeometryDetectInfo: Can't allocate config "
		    "data buffer\n"));
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = NtQueryValueKey(HardwareKey, &unicodeString, KeyValueFullInformation,
			     keyData, VALUE_BUFFER_SIZE, &length);

    if (!NT_SUCCESS(status)) {
	TracePrint((TRACE_LEVEL_ERROR, TRACE_FLAG_GENERAL,
		    "DiskSaveGeometryDetectInfo: Can't query configuration "
		    "data (%#08lx)\n",
		    status));
	FREE_POOL(keyData);
	return status;
    }

    //
    // Extract the resource list out of the key data.
    //

    fullDescriptor = (PCM_FULL_RESOURCE_DESCRIPTOR)(((PUCHAR)keyData) +
						    keyData->DataOffset);
    partialDescriptor = fullDescriptor->PartialResourceList.PartialDescriptors;
    length = partialDescriptor->DeviceSpecificData.DataSize;

    if ((keyData->DataLength < sizeof(CM_FULL_RESOURCE_DESCRIPTOR)) ||
	(fullDescriptor->PartialResourceList.Count == 0) ||
	(partialDescriptor->Type != CmResourceTypeDeviceSpecific) ||
	(length < sizeof(ULONG))) {
	TracePrint((TRACE_LEVEL_ERROR, TRACE_FLAG_GENERAL,
		    "DiskSaveGeometryDetectInfo: BIOS header data too small "
		    "or invalid\n"));
	FREE_POOL(keyData);
	return STATUS_INVALID_PARAMETER;
    }

    //
    // Point to the BIOS data.  THe BIOS data is located after the first
    // partial Resource list which should be device specific data.
    //

    {
	PUCHAR buffer = (PUCHAR)keyData;
	buffer += keyData->DataOffset;
	buffer += sizeof(CM_FULL_RESOURCE_DESCRIPTOR);
	driveParameters = (PCM_INT13_DRIVE_PARAMETER)buffer;
    }

    numberOfDrives = length / sizeof(CM_INT13_DRIVE_PARAMETER);

    //
    // Allocate our detect info list now that we know how many entries there
    // are going to be.  No other routine allocates detect info and this is
    // done out of DriverEntry so we don't need to synchronize it's creation.
    //

    length = sizeof(DISK_DETECT_INFO) * numberOfDrives;
    DetectInfoList = ExAllocatePoolWithTag(length, DISK_TAG_UPDATE_GEOM);

    if (DetectInfoList == NULL) {
	TracePrint((TRACE_LEVEL_ERROR, TRACE_FLAG_GENERAL,
		    "DiskSaveGeometryDetectInfo: Couldn't allocate %x bytes "
		    "for DetectInfoList\n",
		    length));

	FREE_POOL(keyData);
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    DetectInfoCount = numberOfDrives;

    RtlZeroMemory(DetectInfoList, length);

    //
    // Copy the information out of the key data and into the list we've
    // allocated.
    //

    for (i = 0; i < numberOfDrives; i++) {
	DetectInfoList[i].DriveParameters = driveParameters[i];
    }

    FREE_POOL(keyData);
    return STATUS_SUCCESS;
}

/*++

Routine Description:

    The routine queries the registry to determine which disks are visible to
    the BIOS.  If a disk is visable to the BIOS then the geometry information
    is updated with the disk's signature and MBR checksum.

Arguments:

    DriverObject - the object for this driver.
    BusKey - handle to the bus key to be enumerated.

Return Value:

    status

--*/
VOID DiskScanBusDetectInfo(IN PDRIVER_OBJECT DriverObject, IN HANDLE BusKey)
{
    ULONG busNumber;

    NTSTATUS status;

    for (busNumber = 0;; busNumber++) {
	WCHAR buffer[32] = { 0 };
	UNICODE_STRING unicodeString;

	OBJECT_ATTRIBUTES objectAttributes = { 0 };

	HANDLE spareKey;
	HANDLE adapterKey;

	ULONG adapterNumber;

	TracePrint((TRACE_LEVEL_INFORMATION, TRACE_FLAG_GENERAL,
		    "DiskScanBusDetectInfo: Scanning bus %d\n", busNumber));

	//
	// Open controller name key.
	//

	status = RtlStringCchPrintfW(buffer, sizeof(buffer) / sizeof(buffer[0]) - 1,
				     L"%d", busNumber);
	if (!NT_SUCCESS(status)) {
	    TracePrint((TRACE_LEVEL_ERROR, TRACE_FLAG_GENERAL,
			"DiskScanBusDetectInfo: Format symbolic link failed with error: "
			"0x%X\n",
			status));
	    break;
	}

	RtlInitUnicodeString(&unicodeString, buffer);

	InitializeObjectAttributes(&objectAttributes, &unicodeString,
				   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, BusKey,
				   NULL);

	status = NtOpenKey(&spareKey, KEY_READ, &objectAttributes);

	if (!NT_SUCCESS(status)) {
	    TracePrint((TRACE_LEVEL_ERROR, TRACE_FLAG_GENERAL,
			"DiskScanBusDetectInfo: Error %#08lx opening bus "
			"key %#x\n",
			status, busNumber));
	    break;
	}

	//
	// Open up a controller ordinal key.
	//

	RtlInitUnicodeString(&unicodeString, L"DiskController");
	InitializeObjectAttributes(&objectAttributes, &unicodeString,
				   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, spareKey,
				   NULL);

	status = NtOpenKey(&adapterKey, KEY_READ, &objectAttributes);
	NtClose(spareKey);

	if (!NT_SUCCESS(status)) {
	    TracePrint((TRACE_LEVEL_ERROR, TRACE_FLAG_GENERAL,
			"DiskScanBusDetectInfo: Error %#08lx opening "
			"DiskController key\n",
			status));
	    continue;
	}

	for (adapterNumber = 0;; adapterNumber++) {
	    HANDLE diskKey;
	    ULONG diskNumber;

	    //
	    // Open disk key.
	    //

	    TracePrint((TRACE_LEVEL_INFORMATION, TRACE_FLAG_GENERAL,
			"DiskScanBusDetectInfo: Scanning disk key "
			"%d\\DiskController\\%d\\DiskPeripheral\n",
			busNumber, adapterNumber));

	    status = RtlStringCchPrintfW(buffer, sizeof(buffer) / sizeof(buffer[0]) - 1,
					 L"%d\\DiskPeripheral", adapterNumber);
	    if (!NT_SUCCESS(status)) {
		TracePrint((TRACE_LEVEL_ERROR, TRACE_FLAG_GENERAL,
			    "DiskScanBusDetectInfo: Format symbolic link failed with "
			    "error: 0x%X\n",
			    status));
		break;
	    }

	    RtlInitUnicodeString(&unicodeString, buffer);

	    InitializeObjectAttributes(&objectAttributes, &unicodeString,
				       OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
				       adapterKey, NULL);

	    status = NtOpenKey(&diskKey, KEY_READ, &objectAttributes);

	    if (!NT_SUCCESS(status)) {
		TracePrint((TRACE_LEVEL_ERROR, TRACE_FLAG_GENERAL,
			    "DiskScanBusDetectInfo: Error %#08lx opening "
			    "disk key\n",
			    status));
		break;
	    }

	    for (diskNumber = 0;; diskNumber++) {
		HANDLE targetKey;

		TracePrint((TRACE_LEVEL_INFORMATION, TRACE_FLAG_GENERAL,
			    "DiskScanBusDetectInfo: Scanning target key "
			    "%d\\DiskController\\%d\\DiskPeripheral\\%d\n",
			    busNumber, adapterNumber, diskNumber));

		status = RtlStringCchPrintfW(buffer,
					     sizeof(buffer) / sizeof(buffer[0]) - 1,
					     L"%d", diskNumber);
		if (!NT_SUCCESS(status)) {
		    TracePrint((TRACE_LEVEL_ERROR, TRACE_FLAG_GENERAL,
				"DiskScanBusDetectInfo: Format symbolic link failed with "
				"error: 0x%X\n",
				status));
		    break;
		}

		RtlInitUnicodeString(&unicodeString, buffer);

		InitializeObjectAttributes(&objectAttributes, &unicodeString,
					   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
					   diskKey, NULL);

		status = NtOpenKey(&targetKey, KEY_READ, &objectAttributes);

		if (!NT_SUCCESS(status)) {
		    TracePrint((TRACE_LEVEL_ERROR, TRACE_FLAG_GENERAL,
				"DiskScanBusDetectInfo: Error %#08lx "
				"opening target key\n",
				status));
		    break;
		}

		DiskSaveBusDetectInfo(DriverObject, targetKey, diskNumber);

		NtClose(targetKey);
	    }

	    NtClose(diskKey);
	}

	NtClose(adapterKey);
    }

    return;
}

/*++

Routine Description:

    This routine will transfer the firmware/ntdetect reported information
    in the specified target key into the appropriate entry in the
    DetectInfoList.

Arguments:

    DriverObject - the object for this driver.

    TargetKey - the key for the disk being saved.

    DiskNumber - the ordinal of the entry in the DiskPeripheral tree for this
                 entry

Return Value:

    status

--*/
NTSTATUS DiskSaveBusDetectInfo(IN PDRIVER_OBJECT DriverObject, IN HANDLE TargetKey,
			       IN ULONG DiskNumber)
{
    PDISK_DETECT_INFO diskInfo;

    UNICODE_STRING unicodeString;

    PKEY_VALUE_FULL_INFORMATION keyData;
    ULONG length;

    NTSTATUS status;

    UNREFERENCED_PARAMETER(DriverObject);

    if (DiskNumber >= DetectInfoCount) {
	return STATUS_UNSUCCESSFUL;
    }

    diskInfo = &(DetectInfoList[DiskNumber]);

    if (diskInfo->Initialized) {
	NT_ASSERT(FALSE);
	TracePrint((TRACE_LEVEL_ERROR, TRACE_FLAG_GENERAL,
		    "DiskSaveBusDetectInfo: disk entry %#x already has a "
		    "signature of %#08lx and mbr checksum of %#08lx\n",
		    DiskNumber, diskInfo->Signature, diskInfo->MbrCheckSum));
	return STATUS_UNSUCCESSFUL;
    }

    RtlInitUnicodeString(&unicodeString, L"Identifier");

    keyData = ExAllocatePoolWithTag(VALUE_BUFFER_SIZE, DISK_TAG_UPDATE_GEOM);

    if (keyData == NULL) {
	TracePrint((TRACE_LEVEL_ERROR, TRACE_FLAG_GENERAL,
		    "DiskSaveBusDetectInfo: Couldn't allocate space for "
		    "registry data\n"));
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Get disk peripheral identifier.
    //

    status = NtQueryValueKey(TargetKey, &unicodeString, KeyValueFullInformation, keyData,
			     VALUE_BUFFER_SIZE, &length);

    if (!NT_SUCCESS(status)) {
	TracePrint((TRACE_LEVEL_ERROR, TRACE_FLAG_GENERAL,
		    "DiskSaveBusDetectInfo: Error %#08lx getting "
		    "Identifier\n",
		    status));
	FREE_POOL(keyData);
	return status;

    } else if (keyData->DataLength < 9 * sizeof(WCHAR)) {
	//
	// the data is too short to use (we subtract 9 chars in normal path)
	//
	TracePrint((TRACE_LEVEL_ERROR, TRACE_FLAG_GENERAL,
		    "DiskSaveBusDetectInfo: Saved data was invalid, "
		    "not enough data in registry!\n"));
	FREE_POOL(keyData);
	return STATUS_UNSUCCESSFUL;

    } else {
	UNICODE_STRING identifier;
	ULONG value;

	//
	// Complete unicode string.
	//

	identifier.Buffer = (PWSTR)((PUCHAR)keyData + keyData->DataOffset);
	identifier.Length = (USHORT)keyData->DataLength;
	identifier.MaximumLength = (USHORT)keyData->DataLength;

	//
	// Get the first value out of the identifier - this will be the MBR 	// checksum.
	//

	status = RtlUnicodeStringToInteger(&identifier, 16, &value);

	if (!NT_SUCCESS(status)) {
	    TracePrint((TRACE_LEVEL_ERROR, TRACE_FLAG_GENERAL,
			"DiskSaveBusDetectInfo: Error %#08lx converting "
			"identifier %wZ into MBR xsum\n",
			status, &identifier));
	    FREE_POOL(keyData);
	    return status;
	}

	diskInfo->MbrCheckSum = value;

	//
	// Shift the string over to get the disk signature
	//

	identifier.Buffer += 9;
	identifier.Length -= 9 * sizeof(WCHAR);
	identifier.MaximumLength -= 9 * sizeof(WCHAR);

	status = RtlUnicodeStringToInteger(&identifier, 16, &value);

	if (!NT_SUCCESS(status)) {
	    TracePrint((TRACE_LEVEL_ERROR, TRACE_FLAG_GENERAL,
			"DiskSaveBusDetectInfo: Error %#08lx converting "
			"identifier %wZ into disk signature\n",
			status, &identifier));
	    value = 0;
	}

	diskInfo->Signature = value;
    }

    //
    // Here is where we would save away the extended int13 data.
    //

    //
    // Mark this entry as initialized so we can make sure not to do it again.
    //

    diskInfo->Initialized = TRUE;

    FREE_POOL(keyData);

    return STATUS_SUCCESS;
}

/*++

Routine Description:

    This routine checks the DetectInfoList saved away during disk driver init
    to see if any geometry information was reported for this drive.  If the
    geometry data exists (determined by matching non-zero signatures or
    non-zero MBR checksums) then it will be saved in the RealGeometry member
    of the disk data block.

    ClassReadDriveCapacity MUST be called after calling this routine to update
    the cylinder count based on the size of the disk and the presence of any
    disk management software.

Arguments:

    DeviceExtension - Supplies a pointer to the device information for disk.

Return Value:

    Inidicates whether the "RealGeometry" in the data block is now valid.

--*/
DISK_GEOMETRY_SOURCE DiskUpdateGeometry(IN PFUNCTIONAL_DEVICE_EXTENSION FdoExtension)
{
    PDISK_DATA diskData = FdoExtension->CommonExtension.DriverData;

    ULONG i;
    PDISK_DETECT_INFO diskInfo = NULL;

    BOOLEAN found = FALSE;

    NTSTATUS status;

    NT_ASSERT((FdoExtension->DeviceObject->Flags & FILE_REMOVABLE_MEDIA) == 0);

    //
    // If we've already set a non-default geometry for this drive then there's
    // no need to try and update again.
    //

    if (diskData->GeometrySource != DiskGeometryUnknown) {
	return diskData->GeometrySource;
    }

    //
    // Scan through the saved detect info to see if we can find a match
    // for this device.
    //

    for (i = 0; i < DetectInfoCount; i++) {
	NT_ASSERT(DetectInfoList != NULL);

	diskInfo = &(DetectInfoList[i]);

	if ((diskData->Mbr.Signature != 0) &&
	    (diskData->Mbr.Signature == diskInfo->Signature)) {
	    TracePrint((TRACE_LEVEL_INFORMATION, TRACE_FLAG_GENERAL,
			"DiskUpdateGeometry: found match for signature "
			"%#08lx\n",
			diskData->Mbr.Signature));
	    found = TRUE;
	    break;
	} else if ((diskData->Mbr.Signature == 0) && (diskData->Mbr.MbrCheckSum != 0) &&
		   (diskData->Mbr.MbrCheckSum == diskInfo->MbrCheckSum)) {
	    TracePrint((TRACE_LEVEL_INFORMATION, TRACE_FLAG_GENERAL,
			"DiskUpdateGeometry: found match for xsum %#08lx\n",
			diskData->Mbr.MbrCheckSum));
	    found = TRUE;
	    break;
	}
    }

    if (found) {
	ULONG cylinders;
	ULONG sectorsPerTrack;
	ULONG tracksPerCylinder;

	ULONG length;

	//
	// Point to the array of drive parameters.
	//

	cylinders = diskInfo->DriveParameters.MaxCylinders + 1;
	sectorsPerTrack = diskInfo->DriveParameters.SectorsPerTrack;
	tracksPerCylinder = diskInfo->DriveParameters.MaxHeads + 1;

	//
	// Since the BIOS may not report the full drive, recalculate the drive
	// size based on the volume size and the BIOS values for tracks per
	// cylinder and sectors per track..
	//

	length = tracksPerCylinder * sectorsPerTrack;

	if (length == 0) {
	    //
	    // The BIOS information is bogus.
	    //

	    TracePrint((TRACE_LEVEL_INFORMATION, TRACE_FLAG_GENERAL,
			"DiskUpdateGeometry: H (%d) or S(%d) is zero\n",
			tracksPerCylinder, sectorsPerTrack));
	    return DiskGeometryUnknown;
	}

	//
	// since we are copying the structure RealGeometry here, we should
	// really initialize all the fields, especially since a zero'd
	// BytesPerSector field would cause a trap in xHalReadPartitionTable()
	//

	diskData->RealGeometry = FdoExtension->DiskGeometry;

	//
	// Save the geometry information away in the disk data block and
	// set the bit indicating that we found a valid one.
	//

	diskData->RealGeometry.SectorsPerTrack = sectorsPerTrack;
	diskData->RealGeometry.TracksPerCylinder = tracksPerCylinder;
	diskData->RealGeometry.Cylinders.QuadPart = (LONGLONG)cylinders;

	TracePrint((TRACE_LEVEL_INFORMATION, TRACE_FLAG_GENERAL,
		    "DiskUpdateGeometry: BIOS spt %#x, #heads %#x, "
		    "#cylinders %#x\n",
		    sectorsPerTrack, tracksPerCylinder, cylinders));

	diskData->GeometrySource = DiskGeometryFromBios;
	diskInfo->Device = FdoExtension->DeviceObject;

	//
	// Increment the count of used geometry entries.
	//

	InterlockedIncrement(&DetectInfoUsedCount);

    } else {
	TracePrint((TRACE_LEVEL_ERROR, TRACE_FLAG_GENERAL,
		    "DiskUpdateGeometry: no match found for signature %#08lx\n",
		    diskData->Mbr.Signature));
    }

    if (diskData->GeometrySource == DiskGeometryUnknown) {
	//
	// We couldn't find a geometry from the BIOS.  Check with the port
	// driver and see if it can provide one.
	//

	status = DiskGetPortGeometry(FdoExtension, &(diskData->RealGeometry));

	if (NT_SUCCESS(status)) {
	    //
	    // Check the geometry to make sure it's valid.
	    //

	    if ((diskData->RealGeometry.TracksPerCylinder *
		 diskData->RealGeometry.SectorsPerTrack) != 0) {
		diskData->GeometrySource = DiskGeometryFromPort;
		TracePrint((TRACE_LEVEL_INFORMATION, TRACE_FLAG_GENERAL,
			    "DiskUpdateGeometry: using Port geometry for disk %#p\n",
			    FdoExtension));

		if (diskData->RealGeometry.BytesPerSector == 0) {
		    TracePrint((TRACE_LEVEL_ERROR, TRACE_FLAG_GENERAL,
				"DiskDriverReinit: Port driver failed to "
				"set BytesPerSector in the RealGeometry\n"));
		    diskData->RealGeometry.BytesPerSector =
			FdoExtension->DiskGeometry.BytesPerSector;
		    if (diskData->RealGeometry.BytesPerSector == 0) {
			NT_ASSERT(!"BytesPerSector is still zero!");
		    }
		}
	    }
	}
    }

    //
    // If we came up with a "real" geometry for this drive then set it in the
    // device extension.
    //

    if (diskData->GeometrySource != DiskGeometryUnknown) {
	FdoExtension->DiskGeometry = diskData->RealGeometry;
    }

    return diskData->GeometrySource;
}

/*++

Routine Description:

    This routine updates the geometry of the disk.  It will query the port
    driver to see if it can provide any geometry info.  If not it will use
    the current head & sector count.

    Based on these values & the capacity of the drive as reported by
    ClassReadDriveCapacity it will determine a new cylinder count for the
    device.

Arguments:

    Fdo - Supplies the functional device object whos size needs to be updated.

Return Value:

    Returns the status of the opertion.

--*/
NTSTATUS DiskUpdateRemovableGeometry(IN PFUNCTIONAL_DEVICE_EXTENSION FdoExtension)
{
    PCOMMON_DEVICE_EXTENSION commonExtension = &(FdoExtension->CommonExtension);
    PDISK_DATA diskData = commonExtension->DriverData;
    PDISK_GEOMETRY geometry = &(diskData->RealGeometry);

    NTSTATUS status;

    if (FdoExtension->DeviceDescriptor) {
	NT_ASSERT(FdoExtension->DeviceDescriptor->RemovableMedia);
    }
    NT_ASSERT(
	TEST_FLAG(FdoExtension->DeviceObject->Flags, FILE_REMOVABLE_MEDIA));

    //
    // Attempt to determine the disk geometry.  First we'll check with the
    // port driver to see what it suggests for a value.
    //

    status = DiskGetPortGeometry(FdoExtension, geometry);

    if (NT_SUCCESS(status) &&
	((geometry->TracksPerCylinder * geometry->SectorsPerTrack) != 0)) {
	FdoExtension->DiskGeometry = (*geometry);
    }

    return status;
}

/*++

Routine Description:

    This routine will query the port driver for disk geometry.  Some port
    drivers (in particular IDEPORT) may be able to provide geometry for the
    device.

Arguments:

    FdoExtension - the device object for the disk.

    Geometry - a structure to save the geometry information into (if any is
               available)

Return Value:

    STATUS_SUCCESS if geometry information can be provided or
    error status indicating why it can't.

--*/
NTSTATUS DiskGetPortGeometry(IN PFUNCTIONAL_DEVICE_EXTENSION FdoExtension,
			     OUT PDISK_GEOMETRY Geometry)
{
    PCOMMON_DEVICE_EXTENSION commonExtension = &(FdoExtension->CommonExtension);
    PIRP irp;
    PIO_STACK_LOCATION irpStack;
    KEVENT event;

    NTSTATUS status;

    //
    // Build an irp to send IOCTL_DISK_GET_DRIVE_GEOMETRY to the lower driver.
    //

    irp = IoAllocateIrp(commonExtension->LowerDeviceObject->StackSize);

    if (irp == NULL) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    irpStack = IoGetNextIrpStackLocation(irp);

    irpStack->MajorFunction = IRP_MJ_DEVICE_CONTROL;

    irpStack->Parameters.DeviceIoControl.IoControlCode = IOCTL_DISK_GET_DRIVE_GEOMETRY;
    irpStack->Parameters.DeviceIoControl.OutputBufferLength = sizeof(DISK_GEOMETRY);

    irp->SystemBuffer = Geometry;

    KeInitializeEvent(&event, SynchronizationEvent, FALSE);

    IoSetCompletionRoutine(irp, ClassSignalCompletion, &event, TRUE, TRUE, TRUE);

    status = IoCallDriver(commonExtension->LowerDeviceObject, irp);
    if (status == STATUS_PENDING) {
	KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
	status = irp->IoStatus.Status;
    }

    IoFreeIrp(irp);

    return status;
}

/*++

Routine Description:

    The default geometry that was used in partitioning disks under Windows NT 4.0 was

    Sectors per Track   = 0x20 =  32
    Tracks per Cylinder = 0x40 =  64

    This was changed in Windows 2000 to

    Sectors per Track   = 0x3F =  63
    Tracks per Cylinder = 0xFF = 255

    If neither the BIOS nor the port driver can report the correct geometry,  we will
    default to the new numbers on such disks. Now LVM uses the geometry when creating
    logical volumes and dynamic disks.  So reporting an incorrect geometry will cause
    the entire extended partition / dynamic disk to be destroyed

    In this routine, we will look at the Master Boot Record. In 90% of the cases, the
    first entry corresponds to a partition that starts on the first track. If this is
    so,  we shall retrieve the logical block address associated with it and calculate
    the correct geometry.  Now, all partitions start on a cylinder boundary.  So, for
    the remaining 10% we will look at the ending CHS number to determine the geometry

--*/
BOOLEAN DiskIsNT4Geometry(IN PFUNCTIONAL_DEVICE_EXTENSION FdoExtension)
{
    PUSHORT readBuffer = NULL;
    BOOLEAN bFoundNT4 = FALSE;

    readBuffer = ExAllocatePoolWithTag(FdoExtension->DiskGeometry.BytesPerSector,
				       DISK_TAG_UPDATE_GEOM);

    if (readBuffer) {
	KEVENT event;
	LARGE_INTEGER diskOffset;
	IO_STATUS_BLOCK ioStatus = { 0 };
	PIRP irp;

	KeInitializeEvent(&event, SynchronizationEvent, FALSE);

	//
	// Read the Master Boot Record at disk offset 0
	//

	diskOffset.QuadPart = 0;

	irp = IoBuildSynchronousFsdRequest(IRP_MJ_READ, FdoExtension->DeviceObject,
					   readBuffer,
					   FdoExtension->DiskGeometry.BytesPerSector,
					   &diskOffset, &event, &ioStatus);

	if (irp) {
	    PIO_STACK_LOCATION irpSp = IoGetNextIrpStackLocation(irp);
	    NTSTATUS status;

	    irpSp->Flags |= SL_OVERRIDE_VERIFY_VOLUME;

	    status = IoCallDriver(FdoExtension->DeviceObject, irp);

	    if (status == STATUS_PENDING) {
		KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
		status = ioStatus.Status;
	    }

	    if (NT_SUCCESS(status)) {
		//
		// Match the boot record signature
		//

		if (readBuffer[BOOT_SIGNATURE_OFFSET] == BOOT_RECORD_SIGNATURE) {
		    PPARTITION_DESCRIPTOR partitionTableEntry =
			(PPARTITION_DESCRIPTOR)&readBuffer[PARTITION_TABLE_OFFSET];
		    ULONG uCount = 0;

		    //
		    // Walk the entries looking for a clue as to what the geometry might be
		    //

		    for (uCount = 0; uCount < NUM_PARTITION_TABLE_ENTRIES; uCount++) {
			//
			// We are only concerned if there might be a logical volume or if this disk is part of a dynamic set
			//

			if (IsContainerPartition(partitionTableEntry->PartitionType) ||
			    partitionTableEntry->PartitionType == PARTITION_LDM) {
			    //
			    // In 90% of the cases, the first entry corresponds to a partition that starts on the first track
			    //

			    if (partitionTableEntry->StartingTrack == 1 &&
				GET_STARTING_SECTOR(partitionTableEntry) == 0x20) {
				bFoundNT4 = TRUE;
				break;
			    }

			    //
			    // In almost every case, the ending CHS number is on a cylinder boundary
			    //

			    if (partitionTableEntry->EndingTrack == 0x3F &&
				GET_ENDING_S_OF_CHS(partitionTableEntry) == 0x20) {
				bFoundNT4 = TRUE;
				break;
			    }
			}

			partitionTableEntry++;
		    }
		} else {
		    //
		    // The Master Boot Record is invalid
		    //
		}
	    }
	}

	FREE_POOL(readBuffer);
    }

    return bFoundNT4;
}

/*++

Routine Description:

    This routine is used by disk.sys as a wrapper for the classpnp API
    ClassReadDriveCapacity.  It will perform some additional operations to
    attempt to determine drive geometry before it calls the classpnp version
    of the routine.

    For fixed disks this involves calling DiskUpdateGeometry which will check
    various sources (the BIOS, the port driver) for geometry information.

Arguments:

    Fdo - a pointer to the device object to be checked.

Return Value:

    status of ClassReadDriveCapacity.

--*/
NTSTATUS DiskReadDriveCapacity(IN PDEVICE_OBJECT Fdo)
{
    PFUNCTIONAL_DEVICE_EXTENSION fdoExtension = Fdo->DeviceExtension;
    NTSTATUS status;

    if (TEST_FLAG(Fdo->Flags, FILE_REMOVABLE_MEDIA)) {
	DiskUpdateRemovableGeometry(fdoExtension);
    } else {
	DiskUpdateGeometry(fdoExtension);
    }

    status = ClassReadDriveCapacity(Fdo);

    return status;
}

/*++

Routine Description:

    This routine will scan through the current list of disks and attempt to
    match them to any remaining geometry information.  This will only be done
    on the first call to the routine.

    Note: This routine assumes that the system will not be adding or removing
          devices during this phase of the init process.  This is very likely
          a bad assumption but it greatly simplifies the code.

Arguments:

    DriverObject - a pointer to the object for the disk driver.

    Nothing - unused

    Count - an indication of how many times this routine has been called.

Return Value:

    none

--*/
VOID DiskDriverReinitialization(IN PDRIVER_OBJECT DriverObject, IN PVOID Nothing,
				IN ULONG Count)
{
    // Do nothing
}

/*++

Routine Description:

    Get the Int13 information from the BIOS DetectInfoList.

Arguments:

    FdoExtension - Supplies a pointer to the FDO extension that we want to
            obtain the detect information for.

    DetectInfo - A buffer where the detect information will be copied to.

Return Value:

    NTSTATUS code.

--*/
NTSTATUS DiskGetDetectInfo(IN PFUNCTIONAL_DEVICE_EXTENSION FdoExtension,
			   OUT PDISK_DETECTION_INFO DetectInfo)
{
    ULONG i;
    BOOLEAN found = FALSE;
    PDISK_DETECT_INFO diskInfo = NULL;
    PDISK_DATA diskData = FdoExtension->CommonExtension.DriverData;

    //
    // Fail for non-fixed drives.
    //

    if (TEST_FLAG(FdoExtension->DeviceObject->Flags, FILE_REMOVABLE_MEDIA)) {
	return STATUS_NOT_SUPPORTED;
    }

    //
    // There is no GPT detection info, so fail this.
    //

    if (diskData->PartitionStyle == PARTITION_STYLE_GPT) {
	return STATUS_NOT_SUPPORTED;
    }

    for (i = 0; i < DetectInfoCount; i++) {
	NT_ASSERT(DetectInfoList != NULL);

	diskInfo = &(DetectInfoList[i]);

	if ((diskData->Mbr.Signature != 0) &&
	    (diskData->Mbr.Signature == diskInfo->Signature)) {
	    TracePrint((TRACE_LEVEL_INFORMATION, TRACE_FLAG_GENERAL,
			"DiskGetDetectInfo: found match for signature "
			"%#08lx\n",
			diskData->Mbr.Signature));
	    found = TRUE;
	    break;
	} else if ((diskData->Mbr.Signature == 0) && (diskData->Mbr.MbrCheckSum != 0) &&
		   (diskData->Mbr.MbrCheckSum == diskInfo->MbrCheckSum)) {
	    TracePrint((TRACE_LEVEL_INFORMATION, TRACE_FLAG_GENERAL,
			"DiskGetDetectInfo: found match for xsum %#08lx\n",
			diskData->Mbr.MbrCheckSum));
	    found = TRUE;
	    break;
	}
    }

    if (found) {
	DetectInfo->DetectionType = DetectInt13;
	DetectInfo->Int13.DriveSelect = diskInfo->DriveParameters.DriveSelect;
	DetectInfo->Int13.MaxCylinders = diskInfo->DriveParameters.MaxCylinders;
	DetectInfo->Int13.SectorsPerTrack = diskInfo->DriveParameters.SectorsPerTrack;
	DetectInfo->Int13.MaxHeads = diskInfo->DriveParameters.MaxHeads;
	DetectInfo->Int13.NumberDrives = diskInfo->DriveParameters.NumberDrives;
	RtlZeroMemory(&DetectInfo->ExInt13, sizeof(DetectInfo->ExInt13));
    }

    return (found ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL);
}

/*++

Routine Description:

    Read the disks signature from the drive. The signature can be either
    a MBR signature or a GPT/EFI signature.

    The low-level signature reading is done by IoReadDiskSignature().

Arguments:

    Fdo - Pointer to the FDO of a disk to read the signature for.

Return Value:

    NTSTATUS code.

--*/
NTSTATUS DiskReadSignature(IN PDEVICE_OBJECT Fdo)
{
    NTSTATUS Status;
    PFUNCTIONAL_DEVICE_EXTENSION fdoExtension = Fdo->DeviceExtension;
    PDISK_DATA diskData = fdoExtension->CommonExtension.DriverData;
    DISK_SIGNATURE Signature = { 0 };

    Status = IoReadDiskSignature(Fdo, fdoExtension->DiskGeometry.BytesPerSector,
				 &Signature);

    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    if (Signature.PartitionStyle == PARTITION_STYLE_GPT) {
	diskData->PartitionStyle = PARTITION_STYLE_GPT;
	diskData->Efi.DiskId = Signature.Gpt.DiskId;
    } else if (Signature.PartitionStyle == PARTITION_STYLE_MBR) {
	diskData->PartitionStyle = PARTITION_STYLE_MBR;
	diskData->Mbr.Signature = Signature.Mbr.Signature;
	diskData->Mbr.MbrCheckSum = Signature.Mbr.CheckSum;
    } else {
	NT_ASSERT(FALSE);
	Status = STATUS_UNSUCCESSFUL;
    }

    return Status;
}

#endif // defined(_M_IX86) || defined(_M_AMD64)
