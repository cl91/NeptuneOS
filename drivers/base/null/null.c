/*
 * PROJECT:     ReactOS Kernel
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Null Device Driver
 * COPYRIGHT:   Copyright 1998-2018 David Welch (welch@mcmail.com)
 *              Copyright 2007-2018 Alex Ionescu (alex.ionescu@reactos.org)
 */

/* INCLUDES ******************************************************************/

#include <ntddk.h>

/* FUNCTIONS *****************************************************************/

NTAPI NTSTATUS NullQueryFileInformation(OUT PVOID Buffer,
					IN PULONG Length,
					IN FILE_INFORMATION_CLASS InformationClass)
{
    PFILE_STANDARD_INFORMATION StandardInfo = Buffer;

    /* We only support one class */
    if (InformationClass != FileStandardInformation) {
	/* Fail */
	return STATUS_INVALID_INFO_CLASS;
    }

    /* Fill out the information */
    RtlZeroMemory(StandardInfo, sizeof(FILE_STANDARD_INFORMATION));
    StandardInfo->NumberOfLinks = 1;

    /* Return the length and success */
    *Length = sizeof(FILE_STANDARD_INFORMATION);
    return STATUS_SUCCESS;
}

NTAPI BOOLEAN NullRead(IN PFILE_OBJECT FileObject,
		       IN PLARGE_INTEGER FileOffset,
		       IN ULONG Length,
		       IN BOOLEAN Wait,
		       IN ULONG LockKey,
		       OUT PVOID Buffer,
		       OUT PIO_STATUS_BLOCK IoStatus,
		       IN PDEVICE_OBJECT DeviceObject)
{
    /* Complete successfully */
    IoStatus->Status = STATUS_END_OF_FILE;
    IoStatus->Information = 0;
    return TRUE;
}

NTAPI BOOLEAN NullWrite(IN PFILE_OBJECT FileObject,
			IN PLARGE_INTEGER FileOffset,
			IN ULONG Length,
			IN BOOLEAN Wait,
			IN ULONG LockKey,
			IN PVOID Buffer,
			OUT PIO_STATUS_BLOCK IoStatus,
			IN PDEVICE_OBJECT DeviceObject)
{
    /* Complete successfully */
    IoStatus->Status = STATUS_SUCCESS;
    IoStatus->Information = Length;
    return TRUE;
}

NTAPI NTSTATUS NullDispatch(IN PDEVICE_OBJECT DeviceObject,
			    IN PIRP Irp)
{
    PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);

    /* Get the file object and check what kind of request this is */
    switch (IoStack->MajorFunction) {
    case IRP_MJ_CREATE:
    case IRP_MJ_CLOSE:

	/* Complete successfully */
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	break;

    case IRP_MJ_READ:

	/* Return as if we read the entire file */
	Irp->IoStatus.Status = STATUS_END_OF_FILE;
	Irp->IoStatus.Information = 0;
	break;

    case IRP_MJ_WRITE:

	/* Return as if we wrote the entire request */
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = IoStack->Parameters.Write.Length;
	break;

    case IRP_MJ_LOCK_CONTROL:

	/* Dummy */
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	break;

    case IRP_MJ_QUERY_INFORMATION:

	/* Get the length from the request and complete the request */
	ULONG Length = IoStack->Parameters.QueryFile.Length;
	Irp->IoStatus.Status = NullQueryFileInformation(Irp->AssociatedIrp.SystemBuffer, &Length,
							IoStack->Parameters.QueryFile.FileInformationClass);

	/* Return the actual length */
	Irp->IoStatus.Information = Length;
	break;
    }

    /* Complete the request */
    NTSTATUS Status = Irp->IoStatus.Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

NTAPI VOID NullUnload(IN PDRIVER_OBJECT DriverObject)
{
    PDEVICE_OBJECT DeviceObject = DriverObject->DeviceObject;

    /* Delete the Null device */
    IoDeleteDevice(DeviceObject);
}

NTAPI NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject,
			   IN PUNICODE_STRING RegistryPath)
{
    NTSTATUS Status;
    PDEVICE_OBJECT DeviceObject;
    UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\Null");

    UNREFERENCED_PARAMETER(RegistryPath);

    /* Create the Null device */
    Status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_NULL,
			    FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);
    if (!NT_SUCCESS(Status))
	return Status;

    /* Register driver routines */
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = NullDispatch;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = NullDispatch;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = NullDispatch;
    DriverObject->MajorFunction[IRP_MJ_READ] = NullDispatch;
    DriverObject->MajorFunction[IRP_MJ_LOCK_CONTROL] = NullDispatch;
    DriverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION] = NullDispatch;
    DriverObject->DriverUnload = NullUnload;

    /* Return success */
    return STATUS_SUCCESS;
}
