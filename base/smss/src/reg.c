#include <smss.h>

#define SYSTEM_HIVE_PATH	"\\Registry\\Machine\\System"

NTSTATUS SmCreateRegistryKey(IN PCSTR Path,
			     IN BOOLEAN Volatile,
			     OUT OPTIONAL HANDLE *pHandle)
{
    OBJECT_ATTRIBUTES_ANSI ObjAttr;
    InitializeObjectAttributes(&ObjAttr, Path, OBJ_PERMANENT, NULL, NULL);
    HANDLE Handle = NULL;
    RET_ERR_EX(NtCreateKeyA(&Handle, KEY_ALL_ACCESS, &ObjAttr, 0, NULL,
			    Volatile ? REG_OPTION_VOLATILE : REG_OPTION_NON_VOLATILE,
			    NULL),
	       DbgTrace("Failed to create registry key %s\n",
			Path));
    assert(Handle != NULL);
    DbgTrace("Successfully created registry key %s (handle %p)\n",
	     Path, Handle);
    if (pHandle) {
	*pHandle = Handle;
    }
    return STATUS_SUCCESS;
}

NTSTATUS SmSetRegKeyValue(IN HANDLE KeyHandle,
			  IN PCSTR ValueName,
			  IN ULONG Type,
			  IN PVOID Data,
			  IN ULONG DataSize)
{
    RET_ERR_EX(NtSetValueKeyA(KeyHandle, ValueName, 0, Type, Data, DataSize),
	       DbgTrace("Failed to write registry value %s for key handle %p\n",
			ValueName, KeyHandle));
    DbgTrace("Successfully wrote registry value %s for key handle %p\n",
	     ValueName, KeyHandle);
    return STATUS_SUCCESS;
}

NTSTATUS SmInitRegistry()
{
    RET_ERR(SmCreateRegistryKey(SYSTEM_HIVE_PATH, FALSE, NULL));
    return STATUS_SUCCESS;
}
