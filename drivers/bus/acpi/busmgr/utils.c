/*
 *  acpi_utils.c - ACPI Utility Functions ($Revision: 10 $)
 *
 *  Copyright (C) 2001, 2002 Andy Grover <andrew.grover@intel.com>
 *  Copyright (C) 2001, 2002 Paul Diefenbaugh <paul.s.diefenbaugh@intel.com>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or (at
 *  your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#include <stdio.h>
#include <ntddk.h>
#include "../precomp.h"
#include "acpi_bus.h"
#include "acpi_drivers.h"

/* Modified for ReactOS and latest ACPICA
 * Copyright (C)2009  Samuel Serapion
 */

#define _COMPONENT ACPI_BUS_COMPONENT
ACPI_MODULE_NAME("acpi_utils")

static VOID AcpiUtilEvalError(ACPI_HANDLE Handle,
			      ACPI_STRING String,
			      ACPI_STATUS Status)
{
#ifdef ACPI_DEBUG_OUTPUT
    CHAR Prefix[80] = { '\0' };
    ACPI_BUFFER Buffer = { sizeof(Prefix), Prefix };
    AcpiGetName(Handle, ACPI_FULL_PATHNAME, &Buffer);
    ACPI_DEBUG_PRINT((ACPI_DB_INFO, "Evaluate [%s.%s]: %s\n", (PCHAR )Prefix, String,
		      AcpiFormatException(Status)));
#endif
}

/* --------------------------------------------------------------------------
   Object Evaluation Helpers
   -------------------------------------------------------------------------- */
ACPI_STATUS AcpiExtractPackage(ACPI_OBJECT *Package,
			       ACPI_BUFFER *Format,
			       ACPI_BUFFER *Buffer)
{
    UINT32 SizeRequired = 0;
    UINT32 TailOffset = 0;
    PCHAR FormatString = NULL;
    UINT32 FormatCount = 0;
    UINT8 *Head = NULL;
    UINT8 *Tail = NULL;

    if (!Package || (Package->Type != ACPI_TYPE_PACKAGE) ||
	(Package->Package.Count < 1)) {
	ACPI_DEBUG_PRINT((ACPI_DB_WARN, "Invalid 'package' argument\n"));
	return_ACPI_STATUS(AE_BAD_PARAMETER);
    }

    if (!Format || !Format->Pointer || (Format->Length < 1)) {
	ACPI_DEBUG_PRINT((ACPI_DB_WARN, "Invalid 'format' argument\n"));
	return_ACPI_STATUS(AE_BAD_PARAMETER);
    }

    if (!Buffer) {
	ACPI_DEBUG_PRINT((ACPI_DB_WARN, "Invalid 'buffer' argument\n"));
	return_ACPI_STATUS(AE_BAD_PARAMETER);
    }

    FormatCount = (Format->Length / sizeof(char)) - 1;
    if (FormatCount > Package->Package.Count) {
	ACPI_DEBUG_PRINT((ACPI_DB_WARN,
			  "Format specifies more objects [%d] than exist in package [%d].",
			  FormatCount, Package->Package.Count));
	return_ACPI_STATUS(AE_BAD_DATA);
    }

    FormatString = Format->Pointer;

    /*
     * Calculate size_required.
     */
    for (ULONG i = 0; i < FormatCount; i++) {
	ACPI_OBJECT *Element = &(Package->Package.Elements[i]);

	if (!Element) {
	    return_ACPI_STATUS(AE_BAD_DATA);
	}

	switch (Element->Type) {
	case ACPI_TYPE_INTEGER:
	    switch (FormatString[i]) {
	    case 'N':
		SizeRequired += sizeof(ACPI_INTEGER);
		TailOffset += sizeof(ACPI_INTEGER);
		break;
	    case 'S':
		SizeRequired += sizeof(PCHAR ) + sizeof(ACPI_INTEGER) + sizeof(char);
		TailOffset += sizeof(PCHAR );
		break;
	    default:
		ACPI_DEBUG_PRINT((ACPI_DB_WARN,
				  "Invalid package element [%d]: got number, expecting "
				  "[%c].\n",
				  i, FormatString[i]));
		return_ACPI_STATUS(AE_BAD_DATA);
		break;
	    }
	    break;

	case ACPI_TYPE_STRING:
	case ACPI_TYPE_BUFFER:
	    switch (FormatString[i]) {
	    case 'S':
		SizeRequired += sizeof(PCHAR ) +
		    (Element->String.Length * sizeof(char)) + sizeof(char);
		TailOffset += sizeof(PCHAR );
		break;
	    case 'B':
		SizeRequired += sizeof(UINT8 *) +
		    (Element->Buffer.Length * sizeof(UINT8));
		TailOffset += sizeof(UINT8 *);
		break;
	    default:
		ACPI_DEBUG_PRINT((ACPI_DB_WARN,
				  "Invalid package element [%d] got string/buffer, "
				  "expecting [%c].\n",
				  i, FormatString[i]));
		return_ACPI_STATUS(AE_BAD_DATA);
		break;
	    }
	    break;

	case ACPI_TYPE_PACKAGE:
	default:
	    ACPI_DEBUG_PRINT((ACPI_DB_INFO,
			      "Found unsupported element at index=%d\n", i));
	    /* TBD: handle nested packages... */
	    return_ACPI_STATUS(AE_SUPPORT);
	    break;
	}
    }

    /*
     * Validate output buffer.
     */
    if (Buffer->Length < SizeRequired) {
	Buffer->Length = SizeRequired;
	return_ACPI_STATUS(AE_BUFFER_OVERFLOW);
    } else if (Buffer->Length != SizeRequired || !Buffer->Pointer) {
	return_ACPI_STATUS(AE_BAD_PARAMETER);
    }

    Head = Buffer->Pointer;
    Tail = ((PUCHAR)Buffer->Pointer) + TailOffset;

    /*
     * Extract package data.
     */
    for (ULONG i = 0; i < FormatCount; i++) {
	UINT8 **Pointer = NULL;
	ACPI_OBJECT *Element = &(Package->Package.Elements[i]);

	if (!Element) {
	    return_ACPI_STATUS(AE_BAD_DATA);
	}

	switch (Element->Type) {
	case ACPI_TYPE_INTEGER:
	    switch (FormatString[i]) {
	    case 'N':
		*((ACPI_INTEGER *)Head) = Element->Integer.Value;
		Head += sizeof(ACPI_INTEGER);
		break;
	    case 'S':
		Pointer = (UINT8 **)Head;
		*Pointer = Tail;
		*((ACPI_INTEGER *)Tail) = Element->Integer.Value;
		Head += sizeof(ACPI_INTEGER *);
		Tail += sizeof(ACPI_INTEGER);
		/* NULL terminate string */
		*Tail = (char)0;
		Tail += sizeof(char);
		break;
	    default:
		/* Should never get here */
		break;
	    }
	    break;

	case ACPI_TYPE_STRING:
	case ACPI_TYPE_BUFFER:
	    switch (FormatString[i]) {
	    case 'S':
		Pointer = (UINT8 **)Head;
		*Pointer = Tail;
		memcpy(Tail, Element->String.Pointer, Element->String.Length);
		Head += sizeof(PCHAR );
		Tail += Element->String.Length * sizeof(char);
		/* NULL terminate string */
		*Tail = (char)0;
		Tail += sizeof(char);
		break;
	    case 'B':
		Pointer = (UINT8 **)Head;
		*Pointer = Tail;
		memcpy(Tail, Element->Buffer.Pointer, Element->Buffer.Length);
		Head += sizeof(UINT8 *);
		Tail += Element->Buffer.Length * sizeof(UINT8);
		break;
	    default:
		/* Should never get here */
		break;
	    }
	    break;

	case ACPI_TYPE_PACKAGE:
	    /* TBD: handle nested packages... */
	default:
	    /* Should never get here */
	    break;
	}
    }

    return_ACPI_STATUS(AE_OK);
}

ACPI_STATUS AcpiEvaluateInteger(ACPI_HANDLE Handle,
				ACPI_STRING Pathname,
				ACPI_OBJECT_LIST *Arguments,
				ULONG64 *Data)
{
    ACPI_STATUS Status = AE_OK;
    ACPI_OBJECT Element;
    ACPI_BUFFER Buffer = { sizeof(ACPI_OBJECT), &Element };

    ACPI_FUNCTION_TRACE("AcpiEvaluateInteger");

    if (!Data)
	return_ACPI_STATUS(AE_BAD_PARAMETER);

    Status = AcpiEvaluateObject(Handle, Pathname, Arguments, &Buffer);
    if (ACPI_FAILURE(Status)) {
	AcpiUtilEvalError(Handle, Pathname, Status);
	return_ACPI_STATUS(Status);
    }

    if (Element.Type != ACPI_TYPE_INTEGER) {
	AcpiUtilEvalError(Handle, Pathname, AE_BAD_DATA);
	return_ACPI_STATUS(AE_BAD_DATA);
    }

    *Data = Element.Integer.Value;

    ACPI_DEBUG_PRINT((ACPI_DB_INFO, "Return value [%llu]\n", *Data));

    return_ACPI_STATUS(AE_OK);
}

ACPI_STATUS AcpiEvaluateReference(ACPI_HANDLE Handle,
				  ACPI_STRING Pathname,
				  ACPI_OBJECT_LIST *Arguments,
				  PACPI_HANDLE_LIST List)
{
    ACPI_STATUS Status = AE_OK;
    ACPI_OBJECT *Package = NULL;
    ACPI_OBJECT *Element = NULL;
    ACPI_BUFFER Buffer = { ACPI_ALLOCATE_BUFFER, NULL };
    UINT32 i = 0;

    ACPI_FUNCTION_TRACE("AcpiEvaluateReference");

    if (!List) {
	return_ACPI_STATUS(AE_BAD_PARAMETER);
    }

    /* Evaluate object. */

    Status = AcpiEvaluateObject(Handle, Pathname, Arguments, &Buffer);
    if (ACPI_FAILURE(Status))
	goto end;

    Package = (ACPI_OBJECT *)Buffer.Pointer;

    if ((Buffer.Length == 0) || !Package) {
	ACPI_DEBUG_PRINT((ACPI_DB_ERROR, "No return object (len %zX ptr %p)\n",
			  Buffer.Length, Package));
	Status = AE_BAD_DATA;
	AcpiUtilEvalError(Handle, Pathname, Status);
	goto end;
    }
    if (Package->Type != ACPI_TYPE_PACKAGE) {
	ACPI_DEBUG_PRINT(
	    (ACPI_DB_ERROR, "Expecting a [Package], found type %X\n", Package->Type));
	Status = AE_BAD_DATA;
	AcpiUtilEvalError(Handle, Pathname, Status);
	goto end;
    }
    if (!Package->Package.Count) {
	ACPI_DEBUG_PRINT((ACPI_DB_ERROR, "[Package] has zero elements (%p)\n", Package));
	Status = AE_BAD_DATA;
	AcpiUtilEvalError(Handle, Pathname, Status);
	goto end;
    }

    if (Package->Package.Count > ACPI_MAX_HANDLES) {
	return AE_NO_MEMORY;
    }
    List->Count = Package->Package.Count;

    /* Extract package data. */

    for (i = 0; i < List->Count; i++) {
	Element = &(Package->Package.Elements[i]);

	if (Element->Type != ACPI_TYPE_LOCAL_REFERENCE) {
	    Status = AE_BAD_DATA;
	    ACPI_DEBUG_PRINT((ACPI_DB_ERROR,
			      "Expecting a [Reference] package element, found type %X\n",
			      Element->Type));
	    AcpiUtilEvalError(Handle, Pathname, Status);
	    break;
	}

	if (!Element->Reference.Handle) {
	    ACPI_DEBUG_PRINT((ACPI_DB_ERROR,
			      "Invalid reference in"
			      " package %s\n",
			      Pathname));
	    Status = AE_NULL_ENTRY;
	    break;
	}
	/* Get the  ACPI_HANDLE. */

	List->Handles[i] = Element->Reference.Handle;
	ACPI_DEBUG_PRINT((ACPI_DB_INFO, "Found reference [%p]\n", List->Handles[i]));
    }

end:
    if (ACPI_FAILURE(Status)) {
	List->Count = 0;
	//ExFreePool(list->handles);
    }

    if (Buffer.Pointer)
	AcpiOsFree(Buffer.Pointer);

    return_ACPI_STATUS(Status);
}

static NTSTATUS AcpiCreateRegistryTable(HANDLE ParentKeyHandle,
					ACPI_TABLE_HEADER *OutTable,
					PCWSTR KeyName)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING HardwareKeyName, ValueName;
    ANSI_STRING HardwareKeyNameA;
    HANDLE KeyHandle = NULL, SubKeyHandle = NULL;
    NTSTATUS Status;
    CHAR OemId[7] = { 0 }; /* exactly one byte more than ACPI_TABLE_HEADER->OemId */
    CHAR OemTableId[9] = { 0 }; /* exactly one byte more than ACPI_TABLE_HEADER->OemTableId */
    WCHAR OemRevision[9] = { 0 }; /* enough to accept hex DWORD */

    C_ASSERT(sizeof(OemId) == RTL_FIELD_SIZE(ACPI_TABLE_HEADER, OemId) + 1);
    C_ASSERT(sizeof(OemTableId) == RTL_FIELD_SIZE(ACPI_TABLE_HEADER, OemTableId) + 1);
    /* Copy OEM data from the table */
    RtlCopyMemory(OemId, OutTable->OemId, sizeof(OutTable->OemId));
    RtlCopyMemory(OemTableId, OutTable->OemTableId, sizeof(OutTable->OemTableId));
    /* Create table subkey */
    RtlInitUnicodeString(&HardwareKeyName, KeyName);
    InitializeObjectAttributes(&ObjectAttributes, &HardwareKeyName,
			       OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, ParentKeyHandle,
			       NULL);
    Status = NtCreateKey(&KeyHandle, KEY_WRITE, &ObjectAttributes, 0, NULL,
			 REG_OPTION_VOLATILE, NULL);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("NtCreateKey() for %ws failed (Status 0x%08x)\n", KeyName, Status);
	return Status;
    }

    if (OutTable->OemRevision != 0) {
	/* We have OEM info in table, so create other OEM subkeys */
	RtlInitAnsiString(&HardwareKeyNameA, OemId);
	Status = RtlAnsiStringToUnicodeString(&HardwareKeyName, &HardwareKeyNameA, TRUE);
	if (!NT_SUCCESS(Status)) {
	    DPRINT1("RtlAnsiStringToUnicodeString() for %Z failed (Status 0x%08x)\n",
		    &HardwareKeyNameA, Status);
	    NtClose(KeyHandle);
	    return Status;
	}

	InitializeObjectAttributes(&ObjectAttributes, &HardwareKeyName,
				   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, KeyHandle,
				   NULL);
	Status = NtCreateKey(&SubKeyHandle, KEY_WRITE, &ObjectAttributes, 0, NULL,
			     REG_OPTION_VOLATILE, NULL);
	RtlFreeUnicodeString(&HardwareKeyName);
	NtClose(KeyHandle);
	if (!NT_SUCCESS(Status)) {
	    DPRINT1("NtCreateKey() for %Z failed (Status 0x%08x)\n", &HardwareKeyNameA,
		    Status);
	    return Status;
	}
	KeyHandle = SubKeyHandle;

	RtlInitAnsiString(&HardwareKeyNameA, OemTableId);
	Status = RtlAnsiStringToUnicodeString(&HardwareKeyName, &HardwareKeyNameA, TRUE);
	if (!NT_SUCCESS(Status)) {
	    DPRINT1("RtlAnsiStringToUnicodeString() for %Z failed (Status 0x%08x)\n",
		    &HardwareKeyNameA, Status);
	    NtClose(KeyHandle);
	    return Status;
	}

	InitializeObjectAttributes(&ObjectAttributes, &HardwareKeyName,
				   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, KeyHandle,
				   NULL);
	Status = NtCreateKey(&SubKeyHandle, KEY_WRITE, &ObjectAttributes, 0, NULL,
			     REG_OPTION_VOLATILE, NULL);
	RtlFreeUnicodeString(&HardwareKeyName);
	NtClose(KeyHandle);
	if (!NT_SUCCESS(Status)) {
	    DPRINT1("NtCreateKey() for %Z failed (Status 0x%08x)\n", &HardwareKeyNameA,
		    Status);
	    return Status;
	}
	KeyHandle = SubKeyHandle;

	_snwprintf(OemRevision, sizeof(OemRevision), L"%08X",
		   OutTable->OemRevision);
	RtlInitUnicodeString(&HardwareKeyName, OemRevision);
	InitializeObjectAttributes(&ObjectAttributes, &HardwareKeyName,
				   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, KeyHandle,
				   NULL);
	Status = NtCreateKey(&SubKeyHandle, KEY_WRITE, &ObjectAttributes, 0, NULL,
			     REG_OPTION_VOLATILE, NULL);
	NtClose(KeyHandle);
	if (!NT_SUCCESS(Status)) {
	    DPRINT1("NtCreateKey() for %ws failed (Status 0x%08x)\n", KeyName, Status);
	    return Status;
	}
	KeyHandle = SubKeyHandle;
    }
    /* Table reg value name is always '00000000' */
    RtlInitUnicodeString(&ValueName, L"00000000");
    Status = NtSetValueKey(KeyHandle, &ValueName, 0, REG_BINARY, OutTable,
			   OutTable->Length);
    NtClose(KeyHandle);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("NtSetValueKey() failed (Status 0x%08x)\n", Status);
	return Status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS AcpiCreateVolatileRegistryTables(void)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING HardwareKeyName = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\HARDWARE"
							 L"\\ACPI");
    HANDLE KeyHandle = NULL;
    NTSTATUS Status;
    ACPI_STATUS AcpiStatus;
    ACPI_TABLE_HEADER *OutTable;

    /* Create Main Hardware ACPI key*/
    InitializeObjectAttributes(&ObjectAttributes, &HardwareKeyName,
			       OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    Status = NtCreateKey(&KeyHandle, KEY_WRITE, &ObjectAttributes, 0, NULL,
			 REG_OPTION_VOLATILE, NULL);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("NtCreateKey() for ACPI failed (Status 0x%08x)\n", Status);
	return Status;
    }
    /* Read DSDT table */
    AcpiStatus = AcpiGetTable(ACPI_SIG_DSDT, 0, &OutTable);
    if (ACPI_FAILURE(AcpiStatus)) {
	DPRINT1("AcpiGetTable() for DSDT failed (Status 0x%08x)\n", AcpiStatus);
	Status = STATUS_UNSUCCESSFUL;
	goto done;
    }
    /* Dump DSDT table */
    Status = AcpiCreateRegistryTable(KeyHandle, OutTable, L"DSDT");
    if (!NT_SUCCESS(Status)) {
	DPRINT1("AcpiCreateRegistryTable() for DSDT failed (Status 0x%08x)\n",
		Status);
	goto done;
    }
    /* Read FACS table */
    AcpiStatus = AcpiGetTable(ACPI_SIG_FACS, 0, &OutTable);
    if (ACPI_FAILURE(AcpiStatus)) {
	DPRINT1("AcpiGetTable() for FACS failed (Status 0x%08x)\n", AcpiStatus);
	Status = STATUS_UNSUCCESSFUL;
	goto done;
    }
    /* Dump FACS table */
    Status = AcpiCreateRegistryTable(KeyHandle, OutTable, L"FACS");
    if (!NT_SUCCESS(Status)) {
	DPRINT1("AcpiCreateRegistryTable() for FACS failed (Status 0x%08x)\n",
		Status);
	goto done;
    }
    /* Read FACS table */
    AcpiStatus = AcpiGetTable(ACPI_SIG_FADT, 0, &OutTable);
    if (ACPI_FAILURE(AcpiStatus)) {
	DPRINT1("AcpiGetTable() for FADT failed (Status 0x%08x)\n", AcpiStatus);
	Status = STATUS_UNSUCCESSFUL;
	goto done;
    }
    /* Dump FADT table */
    Status = AcpiCreateRegistryTable(KeyHandle, OutTable, L"FADT");
    if (!NT_SUCCESS(Status)) {
	DPRINT1("acpi_dump_table_to_registry() for FADT failed (Status 0x%08x)\n",
		Status);
	goto done;
    }
    OutTable = AcpiOsMapMemory(AcpiOsGetRootSystemTable(), ACPI_XSDT_ENTRY_SIZE);
    if (!OutTable) {
	DPRINT1("AcpiOsMapMemory() failed\n");
	Status = STATUS_NO_MEMORY;
	goto done;
    }
    /* Dump RSDT table */
    Status = AcpiCreateRegistryTable(KeyHandle, OutTable, L"RSDT");
    AcpiOsUnmapMemory(OutTable, ACPI_XSDT_ENTRY_SIZE);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("AcpiCreateRegistryTable() for RSDT failed (Status 0x%08x)\n",
		Status);
    }

done:
    NtClose(KeyHandle);
    return Status;
}
