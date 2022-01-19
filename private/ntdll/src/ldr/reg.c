#include "ldrp.h"

static UNICODE_STRING ImageExecOptionsString =
    RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\"
			L"Windows NT\\CurrentVersion\\Image File Execution Options");
static UNICODE_STRING Wow64OptionsString = RTL_CONSTANT_STRING(L"");

/*
 * Open the root image execution options key and then open the given
 * subkey under it, returning the key handles to both the root key and subkey
 */
NTSTATUS LdrpOpenImageFileOptionsKey(IN PUNICODE_STRING SubKey,
				     IN BOOLEAN Wow64,
				     OUT PHANDLE RootKey,
				     OUT PHANDLE SubKeyHandle)
{
    /* Setup the object attributes */
    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes,
			       Wow64 ? &Wow64OptionsString : &ImageExecOptionsString,
			       OBJ_CASE_INSENSITIVE, NULL, NULL);

    /* Open the root key */
    NTSTATUS Status = NtOpenKey(RootKey, KEY_ENUMERATE_SUB_KEYS, &ObjectAttributes);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    /* Extract the name */
    UNICODE_STRING SubKeyString = *SubKey;
    PWCHAR p1 = (PWCHAR)((ULONG_PTR)SubKeyString.Buffer + SubKeyString.Length);
    while (SubKeyString.Length) {
	if (p1[-1] == L'\\')
	    break;
	p1--;
	SubKeyString.Length -= sizeof(*p1);
    }
    SubKeyString.Buffer = p1;
    SubKeyString.Length = SubKey->Length - SubKeyString.Length;

    /* Setup the object attributes */
    InitializeObjectAttributes(&ObjectAttributes, &SubKeyString,
			       OBJ_CASE_INSENSITIVE, *RootKey, NULL);

    /* Open the setting key */
    return NtOpenKey(SubKeyHandle, GENERIC_READ, &ObjectAttributes);
}

/*
 * @implemented
 */
NTAPI NTSTATUS LdrQueryImageFileKeyOption(IN HANDLE KeyHandle,
					  IN PCWSTR ValueName,
					  IN ULONG Type,
					  OUT PVOID Buffer,
					  IN ULONG BufferSize,
					  OUT PULONG ReturnedLength OPTIONAL)
{
    ULONG KeyInfo[256];
    UNICODE_STRING ValueNameString, IntegerString;
    ULONG KeyInfoSize, ResultSize;
    PKEY_VALUE_PARTIAL_INFORMATION KeyValueInformation = (PKEY_VALUE_PARTIAL_INFORMATION)&KeyInfo;
    BOOLEAN FreeHeap = FALSE;
    NTSTATUS Status;

    /* Build a string for the value name */
    Status = RtlInitUnicodeStringEx(&ValueNameString, ValueName);
    if (!NT_SUCCESS(Status))
	return Status;

    /* Query the value */
    Status = NtQueryValueKey(KeyHandle,
			     &ValueNameString,
			     KeyValuePartialInformation,
			     KeyValueInformation,
			     sizeof(KeyInfo), &ResultSize);
    if (Status == STATUS_BUFFER_OVERFLOW) {
	/* Our local buffer wasn't enough, allocate one */
	KeyInfoSize = sizeof(KEY_VALUE_PARTIAL_INFORMATION) + KeyValueInformation->DataLength;
	KeyValueInformation = RtlAllocateHeap(RtlGetProcessHeap(), 0, KeyInfoSize);
	if (KeyValueInformation != NULL) {
	    /* Try again */
	    Status = NtQueryValueKey(KeyHandle,
				     &ValueNameString,
				     KeyValuePartialInformation,
				     KeyValueInformation,
				     KeyInfoSize, &ResultSize);
	    FreeHeap = TRUE;
	} else {
	    /* Give up this time */
	    Status = STATUS_NO_MEMORY;
	}
    }

    /* Check for success */
    if (NT_SUCCESS(Status)) {
	/* Handle binary data */
	if (KeyValueInformation->Type == REG_BINARY) {
	    /* Check validity */
	    if ((Buffer)
		&& (KeyValueInformation->DataLength <= BufferSize)) {
		/* Copy into buffer */
		RtlMoveMemory(Buffer,
			      &KeyValueInformation->Data,
			      KeyValueInformation->DataLength);
	    } else {
		Status = STATUS_BUFFER_OVERFLOW;
	    }

	    /* Copy the result length */
	    if (ReturnedLength)
		*ReturnedLength = KeyValueInformation->DataLength;
	} else if (KeyValueInformation->Type == REG_DWORD) {
	    /* Check for valid type */
	    if (KeyValueInformation->Type != Type) {
		/* Error */
		Status = STATUS_OBJECT_TYPE_MISMATCH;
	    } else {
		/* Check validity */
		if ((Buffer) && (BufferSize == sizeof(ULONG)) &&
		    (KeyValueInformation->DataLength <= BufferSize)) {
		    /* Copy into buffer */
		    RtlMoveMemory(Buffer,
				  &KeyValueInformation->Data,
				  KeyValueInformation->DataLength);
		} else {
		    Status = STATUS_BUFFER_OVERFLOW;
		}

		/* Copy the result length */
		if (ReturnedLength)
		    *ReturnedLength = KeyValueInformation->DataLength;
	    }
	} else if (KeyValueInformation->Type != REG_SZ) {
	    /* We got something weird */
	    Status = STATUS_OBJECT_TYPE_MISMATCH;
	} else {
	    /*  String, check what you requested */
	    if (Type == REG_DWORD) {
		/* Validate */
		if (BufferSize != sizeof(ULONG)) {
		    /* Invalid size */
		    BufferSize = 0;
		    Status = STATUS_INFO_LENGTH_MISMATCH;
		} else {
		    /* OK, we know what you want... */
		    IntegerString.Buffer =
			(PWSTR) KeyValueInformation->Data;
		    IntegerString.Length =
			(USHORT) KeyValueInformation->DataLength -
			sizeof(WCHAR);
		    IntegerString.MaximumLength =
			(USHORT) KeyValueInformation->DataLength;
		    Status =
			RtlUnicodeStringToInteger(&IntegerString, 0,
						  (PULONG) Buffer);
		}
	    } else {
		/* Validate */
		if (KeyValueInformation->DataLength > BufferSize) {
		    /* Invalid */
		    Status = STATUS_BUFFER_OVERFLOW;
		} else {
		    /* Set the size */
		    BufferSize = KeyValueInformation->DataLength;
		}

		/* Copy the string */
		RtlMoveMemory(Buffer, &KeyValueInformation->Data,
			      BufferSize);
	    }

	    /* Copy the result length */
	    if (ReturnedLength)
		*ReturnedLength = KeyValueInformation->DataLength;
	}
    }

    /* Check if buffer was in heap */
    if (FreeHeap)
	RtlFreeHeap(RtlGetProcessHeap(), 0, KeyValueInformation);

    /* Return status */
    return Status;
}

/*
 * @implemented
 */
NTAPI NTSTATUS LdrQueryImageFileExecutionOptionsEx(IN PUNICODE_STRING SubKey,
						   IN PCWSTR ValueName,
						   IN ULONG Type,
						   OUT PVOID Buffer,
						   IN ULONG BufferSize,
						   OUT PULONG ReturnedLength OPTIONAL,
						   IN BOOLEAN Wow64)
{
    HANDLE RootKey;
    HANDLE SubKeyHandle;
    /* Open a handle to the key */
    NTSTATUS Status = LdrpOpenImageFileOptionsKey(SubKey, Wow64, &RootKey, &SubKeyHandle);

    /* Check for success */
    if (NT_SUCCESS(Status)) {
	/* Query the data */
	Status = LdrQueryImageFileKeyOption(SubKeyHandle, ValueName, Type, Buffer,
					    BufferSize, ReturnedLength);

	/* Close the key */
	NtClose(SubKeyHandle);
	NtClose(RootKey);
    }

    /* Return to caller */
    return Status;
}

/*
 * @implemented
 */
NTAPI NTSTATUS LdrQueryImageFileExecutionOptions(IN PUNICODE_STRING SubKey,
						 IN PCWSTR ValueName,
						 IN ULONG Type,
						 OUT PVOID Buffer,
						 IN ULONG BufferSize,
						 OUT PULONG ReturnedLength OPTIONAL)
{
    /* Call the newer function */
    return LdrQueryImageFileExecutionOptionsEx(SubKey,
					       ValueName,
					       Type,
					       Buffer,
					       BufferSize,
					       ReturnedLength, FALSE);
}
