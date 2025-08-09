/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Module Name:

    hardware.c

Abstract:

    The Native Command Line Interface is the command shell for Neptune OS.
    This module implements hardware information database queries.

Environment:

    Native mode

Revision History:

    Alex Ionescu - Started Implementation - 23-Mar-06

--*/
#include "ntcmd.h"

#define MAX_DEVICE_ID_LEN   200
#define ROOT_NAME           L"HTREE\\ROOT\\0"

static NTSTATUS RtlCliGetEnumKey(OUT PHANDLE KeyHandle)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING KeyName =
	RTL_CONSTANT_STRING(L"\\Registry\\Machine\\System\\CurrentControlSet\\Enum");

    //
    // Initialize the object attributes
    //
    InitializeObjectAttributes(&ObjectAttributes,
			       &KeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    //
    // Open the key for read access
    //
    return NtOpenKey(KeyHandle, KEY_READ, &ObjectAttributes);
}

static NTSTATUS RtlCliGetChildOrSibling(IN PWCHAR Name,
					OUT PWCHAR ChildName,
					IN ULONG Type)
{
    NTSTATUS Status;
    PLUGPLAY_CONTROL_RELATED_DEVICE_DATA PlugPlayData;

    //
    // Initialize the Root Device Node name
    //
    RtlInitUnicodeString(&PlugPlayData.TargetDeviceInstance, Name);

    //
    // Initialize the request
    //
    PlugPlayData.Relation = Type;
    PlugPlayData.RelatedDeviceInstanceLength = MAX_DEVICE_ID_LEN;
    PlugPlayData.RelatedDeviceInstance = ChildName;

    //
    // Get the root child node
    //
    Status = NtPlugPlayControl(PlugPlayControlGetRelatedDevice,
			       (PVOID)&PlugPlayData,
			       sizeof(PLUGPLAY_CONTROL_RELATED_DEVICE_DATA));
    return Status;
}

static NTSTATUS RtlCliPrintDeviceName(IN PWCHAR Name,
				      IN ULONG Level,
				      IN HANDLE RootKey)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PKEY_VALUE_FULL_INFORMATION FullInformation;
    ULONG ResultLength;
    CHAR Indentation[MAX_DEVICE_ID_LEN];

    //
    // We must have a root key
    //
    if (!RootKey) {
	return STATUS_INVALID_HANDLE;
    }

    //
    // Root key opened, now initialize the device instance key name
    //
    UNICODE_STRING KeyName;
    RtlInitUnicodeString(&KeyName, Name);

    //
    // Setup the object attributes and open the key
    //
    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes,
			       &KeyName, 0, RootKey, NULL);
    HANDLE RegHandle = NULL;
    Status = NtOpenKey(&RegHandle, KEY_READ, &ObjectAttributes);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }

    //
    // Setup and allocate the key data structure
    //
    ResultLength = sizeof(*FullInformation) + 256;
    FullInformation = RtlAllocateHeap(RtlGetProcessHeap(),
				      0, ResultLength);

    //
    // Now check for a friendly name
    //
    RtlInitUnicodeString(&KeyName, L"FriendlyName");
    Status = NtQueryValueKey(RegHandle,
			     &KeyName,
			     KeyValueFullInformation,
			     FullInformation,
			     ResultLength, &ResultLength);
    if (!NT_SUCCESS(Status)) {
	//
	// No friendly name found, try the device description key
	//
	RtlInitUnicodeString(&KeyName, L"DeviceDesc");
	Status = NtQueryValueKey(RegHandle,
				 &KeyName,
				 KeyValueFullInformation,
				 FullInformation,
				 ResultLength, &ResultLength);
    }

    //
    // Check if we have success until here
    //
    if (!NT_SUCCESS(Status)) {
	goto out;
    }

    //
    // Get the pointer to the name
    //
    Name = (PWCHAR)((ULONG_PTR)FullInformation + FullInformation->DataOffset);

    //
    // Indent the name to create the appeareance of a tree
    //
out:
    for (ULONG i = 0; i < (Level * 2); i++)
	Indentation[i] = ' ';
    Indentation[Level * 2] = '\0';

    //
    // Add the device name or description, and display it
    //
    RtlCliDisplayString("%s%ws\n", Indentation, Name);

    //
    // Close the key to the device instance name
    //
    if (RegHandle) {
	NtClose(RegHandle);
    }

    //
    // Return status to caller
    //
    return Status;
}

static VOID RtlCliListSubNodes(IN PWCHAR DeviceInstance,
			       IN HANDLE RootKey,
			       IN ULONG Level)
{
    NTSTATUS Status;
    WCHAR RelatedDevice[MAX_DEVICE_ID_LEN] = L"\0";

    //
    // Print the node name
    //
again:
    RtlCliPrintDeviceName(DeviceInstance, Level, RootKey);

    //
    // Get its children
    //
    Status = RtlCliGetChildOrSibling(DeviceInstance, RelatedDevice,
				     PNP_GET_CHILD_DEVICE);
    if (NT_SUCCESS(Status)) {
	//
	// Get its children's subnodes
	//
	RtlCliListSubNodes(RelatedDevice, RootKey, Level + 1);
    }

    //
    // Get the first sibling
    //
    Status = RtlCliGetChildOrSibling(DeviceInstance, RelatedDevice,
				     PNP_GET_SIBLING_DEVICE);
    if (NT_SUCCESS(Status)) {
	//
	// Move to the next sibling
	//
	RtlCopyMemory(DeviceInstance, RelatedDevice,
		      (wcslen(RelatedDevice)+1) * sizeof(WCHAR));
	goto again;
    }
}

NTSTATUS RtlCliListHardwareTree(VOID)
{
    NTSTATUS Status;

    HANDLE RootKey = NULL;
    Status = RtlCliGetEnumKey(&RootKey);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    //
    // Now get the entire tree
    //
    WCHAR DeviceInstance[MAX_DEVICE_ID_LEN] = ROOT_NAME;
    RtlCliListSubNodes(DeviceInstance, RootKey, 0);
    NtClose(RootKey);
    return STATUS_SUCCESS;
}
