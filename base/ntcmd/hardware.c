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

ULONG Level = 0;
HANDLE RootKey = 0;

NTSTATUS RtlCliGetEnumKey(OUT PHANDLE KeyHandle)
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

NTSTATUS RtlCliGetChildOrSibling(IN PWCHAR Name,
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

NTSTATUS RtlCliPrintDeviceName(IN PWCHAR Name)
{
    NTSTATUS Status = STATUS_SUCCESS;
    HANDLE RegHandle;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING KeyName;
    PKEY_VALUE_FULL_INFORMATION FullInformation;
    ULONG ResultLength;
    WCHAR Buffer[MAX_DEVICE_ID_LEN];
    ULONG i;

    //
    // If we don't already have a root key, get it now
    //
    if (!RootKey)
	Status = RtlCliGetEnumKey(&RootKey);
    if (NT_SUCCESS(Status)) {
	//
	// Root key opened, now initialize the device instance key name
	//
	RtlInitUnicodeString(&KeyName, Name);

	//
	// Setup the object attributes and open the key
	//
	InitializeObjectAttributes(&ObjectAttributes,
				   &KeyName, 0, RootKey, NULL);
	Status = NtOpenKey(&RegHandle, KEY_READ, &ObjectAttributes);
	if (NT_SUCCESS(Status)) {
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
	    if (NT_SUCCESS(Status)) {
		//
		// Get the pointer to the name
		//
		Name = (PWCHAR)((ULONG_PTR)FullInformation + FullInformation->DataOffset);

		//
		// Indent the name to create the appeareance of a tree
		//
		for (i = 0; i < (Level * 2); i++)
		    Buffer[i] = ' ';
		Buffer[i] = UNICODE_NULL;

		//
		// Add the device name or description, and display it
		//
		wcscat_s(Buffer, MAX_DEVICE_ID_LEN, Name);
		RtlCliDisplayString("%ws\n", Buffer);
		DbgPrint("%ws\n", Buffer);
	    }
	    //
	    // Close the key to the device instance name
	    //
	    NtClose(RegHandle);
	}
    }
    //
    // Return status to caller
    //
    return Status;
}

NTSTATUS RtlCliListSubNodes(IN PWCHAR Parent,
			    IN PWCHAR Sibling,
			    IN PWCHAR Current)
{
    NTSTATUS Status;
    WCHAR FoundSibling[MAX_DEVICE_ID_LEN];
    WCHAR FoundChild[MAX_DEVICE_ID_LEN];

    //
    // Start looping
    //
    do {
	//
	// Get the first sibling
	//
	Status = RtlCliGetChildOrSibling(Current, FoundSibling,
					 PNP_GET_SIBLING_DEVICE);
	if (!NT_SUCCESS(Status))
	    *FoundSibling = UNICODE_NULL;

	//
	// Print its name
	//
	Status = RtlCliPrintDeviceName(Current);

	//
	// Get its children
	//
	Status = RtlCliGetChildOrSibling(Current, FoundChild,
					 PNP_GET_CHILD_DEVICE);
	if (NT_SUCCESS(Status)) {
	    //
	    // Get it's children's subnodes
	    //
	    Level++;
	    RtlCliListSubNodes(Current, NULL, FoundChild);
	    Level--;
	}
	//
	// Move to the next sibling
	//
	Current = FoundSibling;
    } while (*Current);

    //
    // Return status
    //
    return Status;
}

NTSTATUS RtlCliListHardwareTree(VOID)
{
    NTSTATUS Status;
    WCHAR Buffer[MAX_DEVICE_ID_LEN];

    //
    // Get the root node's child
    //
    Status = RtlCliGetChildOrSibling(ROOT_NAME, Buffer, PNP_GET_CHILD_DEVICE);

    //
    // Now get the entire tree
    //
    Status = RtlCliListSubNodes(ROOT_NAME, NULL, Buffer);
    return Status;
}
