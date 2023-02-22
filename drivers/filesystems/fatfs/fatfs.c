/*
 * PROJECT:     FAT Filesystem
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Driver entry interface
 * COPYRIGHT:   Copyright 1998 Jason Filby <jasonfilby@yahoo.com>
 *              Copyright 2010-2018 Pierre Schweitzer <pierre@reactos.org>
 */

/* INCLUDES *****************************************************************/

#include "fatfs.h"

/* GLOBALS *****************************************************************/

PFAT_GLOBAL_DATA FatGlobalData;

/* FUNCTIONS ****************************************************************/

/*
 * FUNCTION: Called by the system to initialize the driver
 * ARGUMENTS:
 *           DriverObject = object describing this driver
 *           RegistryPath = path to our configuration entries
 * RETURNS: Success or failure
 */
NTSTATUS NTAPI DriverEntry(IN PDRIVER_OBJECT DriverObject,
			   IN PUNICODE_STRING RegistryPath)
{
    PDEVICE_OBJECT DeviceObject;
    UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\FatX");
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(RegistryPath);

    Status = IoCreateDevice(DriverObject,
			    sizeof(FAT_GLOBAL_DATA),
			    &DeviceName,
			    FILE_DEVICE_DISK_FILE_SYSTEM,
			    0, FALSE, &DeviceObject);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    FatGlobalData = DeviceObject->DeviceExtension;
    RtlZeroMemory(FatGlobalData, sizeof(FAT_GLOBAL_DATA));
    FatGlobalData->DriverObject = DriverObject;
    FatGlobalData->DeviceObject = DeviceObject;
    FatGlobalData->NumberProcessors = KeNumberProcessors;
    /* Enable this to enter the debugger when file system corruption
     * has been detected:
     FatGlobalData->Flags = FAT_BREAK_ON_CORRUPTION; */

    /* Delayed close support */
    ExInitializeFastMutex(&FatGlobalData->CloseMutex);
    InitializeListHead(&FatGlobalData->CloseListHead);
    FatGlobalData->CloseCount = 0;
    FatGlobalData->CloseWorkerRunning = FALSE;
    FatGlobalData->ShutdownStarted = FALSE;
    FatGlobalData->CloseWorkItem = IoAllocateWorkItem(DeviceObject);
    if (FatGlobalData->CloseWorkItem == NULL) {
	IoDeleteDevice(DeviceObject);
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    DeviceObject->Flags |= DO_DIRECT_IO;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = FatBuildRequest;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = FatBuildRequest;
    DriverObject->MajorFunction[IRP_MJ_READ] = FatBuildRequest;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = FatBuildRequest;
    DriverObject->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL] =
	FatBuildRequest;
    DriverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION] =
	FatBuildRequest;
    DriverObject->MajorFunction[IRP_MJ_SET_INFORMATION] = FatBuildRequest;
    DriverObject->MajorFunction[IRP_MJ_DIRECTORY_CONTROL] =
	FatBuildRequest;
    DriverObject->MajorFunction[IRP_MJ_QUERY_VOLUME_INFORMATION] =
	FatBuildRequest;
    DriverObject->MajorFunction[IRP_MJ_SET_VOLUME_INFORMATION] =
	FatBuildRequest;
    DriverObject->MajorFunction[IRP_MJ_SHUTDOWN] = FatShutdown;
    DriverObject->MajorFunction[IRP_MJ_LOCK_CONTROL] = FatBuildRequest;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = FatBuildRequest;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = FatBuildRequest;
    DriverObject->MajorFunction[IRP_MJ_FLUSH_BUFFERS] = FatBuildRequest;
    DriverObject->MajorFunction[IRP_MJ_PNP] = FatBuildRequest;

    DriverObject->DriverUnload = NULL;

    /* Cache manager */
    FatGlobalData->CacheMgrCallbacks.AcquireForLazyWrite =
	FatAcquireForLazyWrite;
    FatGlobalData->CacheMgrCallbacks.ReleaseFromLazyWrite =
	FatReleaseFromLazyWrite;
    FatGlobalData->CacheMgrCallbacks.AcquireForReadAhead =
	FatAcquireForLazyWrite;
    FatGlobalData->CacheMgrCallbacks.ReleaseFromReadAhead =
	FatReleaseFromLazyWrite;

    /* Private lists */
    ExInitializeNPagedLookasideList(&FatGlobalData->FcbLookasideList,
				    NULL, NULL, 0, sizeof(FATFCB),
				    TAG_FCB, 0);
    ExInitializeNPagedLookasideList(&FatGlobalData->CcbLookasideList, NULL,
				    NULL, 0, sizeof(FATCCB), TAG_CCB, 0);
    ExInitializeNPagedLookasideList(&FatGlobalData->
				    IrpContextLookasideList, NULL, NULL, 0,
				    sizeof(FAT_IRP_CONTEXT), TAG_IRP, 0);
    ExInitializePagedLookasideList(&FatGlobalData->
				   CloseContextLookasideList, NULL, NULL,
				   0, sizeof(FAT_CLOSE_CONTEXT),
				   TAG_CLOSE, 0);

    ExInitializeResourceLite(&FatGlobalData->VolumeListLock);
    InitializeListHead(&FatGlobalData->VolumeListHead);
    IoRegisterFileSystem(DeviceObject);

    return STATUS_SUCCESS;
}
