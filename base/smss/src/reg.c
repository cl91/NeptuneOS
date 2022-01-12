#include <smss.h>

#define SYSTEM_HIVE_PATH	L"\\Registry\\Machine\\System"
#define SYSTEM_HIVE_PATH_LENGTH	(sizeof(SYSTEM_HIVE_PATH)-2)

NTSTATUS SmInitRegistry()
{
    HANDLE SystemHive;
    DECLARE_UNICODE_STRING(Path, SYSTEM_HIVE_PATH, SYSTEM_HIVE_PATH_LENGTH);
    OBJECT_ATTRIBUTES ObjAttr;
    InitializeObjectAttributes(&ObjAttr, &Path, OBJ_PERMANENT, NULL, NULL);
    RET_ERR_EX(NtCreateKey(&SystemHive, KEY_ALL_ACCESS, &ObjAttr, 0, NULL,
			   REG_OPTION_NON_VOLATILE, NULL),
	       DbgTrace("Failed to create registry key %wZ\n",
			&Path));
    DbgTrace("Successfully created registry key %wZ (handle %p)\n",
	     &Path, SystemHive);
    return STATUS_SUCCESS;
}
