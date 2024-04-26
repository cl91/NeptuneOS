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

const char *MajorFunctionNames[] = {
    "IRP_MJ_CREATE",
    "IRP_MJ_CREATE_NAMED_PIPE",
    "IRP_MJ_CLOSE",
    "IRP_MJ_READ",
    "IRP_MJ_WRITE",
    "IRP_MJ_QUERY_INFORMATION",
    "IRP_MJ_SET_INFORMATION",
    "IRP_MJ_QUERY_EA",
    "IRP_MJ_SET_EA",
    "IRP_MJ_FLUSH_BUFFERS",
    "IRP_MJ_QUERY_VOLUME_INFORMATION",
    "IRP_MJ_SET_VOLUME_INFORMATION",
    "IRP_MJ_DIRECTORY_CONTROL",
    "IRP_MJ_FILE_SYSTEM_CONTROL",
    "IRP_MJ_DEVICE_CONTROL",
    "IRP_MJ_INTERNAL_DEVICE_CONTROL",
    "IRP_MJ_SHUTDOWN",
    "IRP_MJ_LOCK_CONTROL",
    "IRP_MJ_CLEANUP",
    "IRP_MJ_CREATE_MAILSLOT",
    "IRP_MJ_QUERY_SECURITY",
    "IRP_MJ_SET_SECURITY",
    "IRP_MJ_POWER",
    "IRP_MJ_SYSTEM_CONTROL",
    "IRP_MJ_DEVICE_CHANGE",
    "IRP_MJ_QUERY_QUOTA",
    "IRP_MJ_SET_QUOTA",
    "IRP_MJ_PNP",
    "IRP_MJ_MAXIMUM_FUNCTION"
};

/* FUNCTIONS ****************************************************************/

static DRIVER_DISPATCH FatBuildRequest;

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
    UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\FileSystem\\FatX");
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(RegistryPath);

    Status = IoCreateDevice(DriverObject, sizeof(FAT_GLOBAL_DATA), &DeviceName,
			    FILE_DEVICE_DISK_FILE_SYSTEM, 0, FALSE, &DeviceObject);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    FatGlobalData = DeviceObject->DeviceExtension;
    RtlZeroMemory(FatGlobalData, sizeof(FAT_GLOBAL_DATA));
    FatGlobalData->DriverObject = DriverObject;
    FatGlobalData->DeviceObject = DeviceObject;
    /* TODO: We need to figure out SMP (one queue per processor?) */
    FatGlobalData->NumberProcessors = 1;

    /* Generate an assertion when file system corruption has been detected. */
    FatGlobalData->Flags = FAT_BREAK_ON_CORRUPTION;

    DriverObject->MajorFunction[IRP_MJ_CLOSE] = FatBuildRequest;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = FatBuildRequest;
    DriverObject->MajorFunction[IRP_MJ_READ] = FatBuildRequest;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = FatBuildRequest;
    DriverObject->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL] = FatBuildRequest;
    DriverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION] = FatBuildRequest;
    DriverObject->MajorFunction[IRP_MJ_SET_INFORMATION] = FatBuildRequest;
    DriverObject->MajorFunction[IRP_MJ_DIRECTORY_CONTROL] = FatBuildRequest;
    DriverObject->MajorFunction[IRP_MJ_QUERY_VOLUME_INFORMATION] = FatBuildRequest;
    DriverObject->MajorFunction[IRP_MJ_SET_VOLUME_INFORMATION] = FatBuildRequest;
    DriverObject->MajorFunction[IRP_MJ_SHUTDOWN] = FatShutdown;
    DriverObject->MajorFunction[IRP_MJ_LOCK_CONTROL] = FatBuildRequest;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = FatBuildRequest;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = FatBuildRequest;
    DriverObject->MajorFunction[IRP_MJ_FLUSH_BUFFERS] = FatBuildRequest;
    DriverObject->MajorFunction[IRP_MJ_PNP] = FatBuildRequest;

    DriverObject->DriverUnload = NULL;

    /* Private lists */
    ExInitializeLookasideList(&FatGlobalData->FcbLookasideList,
			      NULL, NULL, sizeof(FATFCB), TAG_FCB);
    ExInitializeLookasideList(&FatGlobalData->CcbLookasideList,
			      NULL, NULL, sizeof(FATCCB), TAG_CCB);
    ExInitializeLookasideList(&FatGlobalData->IrpContextLookasideList,
			      NULL, NULL, sizeof(FAT_IRP_CONTEXT), TAG_IRP);

    InitializeListHead(&FatGlobalData->VolumeListHead);
    return IoRegisterFileSystem(DeviceObject);
}

static PFAT_IRP_CONTEXT FatAllocateIrpContext(PDEVICE_OBJECT DeviceObject,
					      PIRP Irp)
{
    DPRINT("FatAllocateIrpContext(DeviceObject %p, Irp %p)\n",
	   DeviceObject, Irp);

    ASSERT(DeviceObject);
    ASSERT(Irp);

    PFAT_IRP_CONTEXT IrpContext =
	ExAllocateFromLookasideList(&FatGlobalData->IrpContextLookasideList);
    if (IrpContext) {
	RtlZeroMemory(IrpContext, sizeof(FAT_IRP_CONTEXT));
	IrpContext->Irp = Irp;
	IrpContext->DeviceObject = DeviceObject;
	IrpContext->DeviceExt = DeviceObject->DeviceExtension;
	IrpContext->Stack = IoGetCurrentIrpStackLocation(Irp);
	ASSERT(IrpContext->Stack);
	IrpContext->MajorFunction = IrpContext->Stack->MajorFunction;
	IrpContext->MinorFunction = IrpContext->Stack->MinorFunction;
	IrpContext->FileObject = IrpContext->Stack->FileObject;
	IrpContext->PriorityBoost = IO_NO_INCREMENT;
    }
    return IrpContext;
}

static VOID FatFreeIrpContext(PFAT_IRP_CONTEXT IrpContext)
{
    ASSERT(IrpContext);
    ExFreeToLookasideList(&FatGlobalData->IrpContextLookasideList, IrpContext);
}

static NTSTATUS FatDeviceControl(IN PFAT_IRP_CONTEXT IrpContext)
{
    return IoCallDriver(IrpContext->DeviceExt->StorageDevice,
			IrpContext->Irp);
}

static NTSTATUS FatDispatchRequest(IN PFAT_IRP_CONTEXT IrpContext)
{
    NTSTATUS Status;

    DPRINT("FatDispatchRequest (IrpContext %p), is called for %s\n",
	   IrpContext, IrpContext->MajorFunction >= IRP_MJ_MAXIMUM_FUNCTION ? "????" :
	   MajorFunctionNames[IrpContext->MajorFunction]);

    ASSERT(IrpContext);

    switch (IrpContext->MajorFunction) {
    case IRP_MJ_CLOSE:
	Status = FatClose(IrpContext);
	break;

    case IRP_MJ_CREATE:
	Status = FatCreate(IrpContext);
	break;

    case IRP_MJ_READ:
	Status = FatRead(IrpContext);
	break;

    case IRP_MJ_WRITE:
	Status = FatWrite(&IrpContext);
	break;

    case IRP_MJ_FILE_SYSTEM_CONTROL:
	Status = FatFileSystemControl(IrpContext);
	break;

    case IRP_MJ_QUERY_INFORMATION:
	Status = FatQueryInformation(IrpContext);
	break;

    case IRP_MJ_SET_INFORMATION:
	Status = FatSetInformation(IrpContext);
	break;

    case IRP_MJ_DIRECTORY_CONTROL:
	Status = FatDirectoryControl(IrpContext);
	break;

    case IRP_MJ_QUERY_VOLUME_INFORMATION:
	Status = FatQueryVolumeInformation(IrpContext);
	break;

    case IRP_MJ_SET_VOLUME_INFORMATION:
	Status = FatSetVolumeInformation(IrpContext);
	break;

    case IRP_MJ_LOCK_CONTROL:
	/* File lock control is implemented on the server side. */
	Status = STATUS_NOT_IMPLEMENTED;
	break;

    case IRP_MJ_DEVICE_CONTROL:
	Status = FatDeviceControl(IrpContext);
	break;

    case IRP_MJ_CLEANUP:
	Status = FatCleanup(IrpContext);
	break;

    case IRP_MJ_FLUSH_BUFFERS:
	Status = FatFlush(IrpContext);
	break;

    case IRP_MJ_PNP:
	Status = FatPnp(IrpContext);
	break;

    default:
	DPRINT1("Unexpected major function %x\n",
		IrpContext->MajorFunction);
	Status = STATUS_DRIVER_INTERNAL_ERROR;
    }

    if (IrpContext != NULL) {
	if (Status != STATUS_PENDING) {
	    /* If IRP is not forwarded, complete the IRP. */
	    IrpContext->Irp->IoStatus.Status = Status;
	    IoCompleteRequest(IrpContext->Irp, IrpContext->PriorityBoost);
	}
	/* In either case we need to free the IRP context. */
	FatFreeIrpContext(IrpContext);
    }

    return Status;
}

static NTSTATUS FatBuildRequest(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS Status;
    PFAT_IRP_CONTEXT IrpContext;

    DPRINT("FatBuildRequest (DeviceObject %p, Irp %p)\n", DeviceObject, Irp);

    ASSERT(DeviceObject);
    ASSERT(Irp);

    IrpContext = FatAllocateIrpContext(DeviceObject, Irp);
    if (IrpContext == NULL) {
	Status = STATUS_INSUFFICIENT_RESOURCES;
	Irp->IoStatus.Status = Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
    } else {
	Status = FatDispatchRequest(IrpContext);
    }
    return Status;
}
