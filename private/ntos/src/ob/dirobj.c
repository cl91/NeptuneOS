#include "obp.h"

POBJECT_DIRECTORY ObpRootObjectDirectory;

/*
 * Called when Executive components attempt to create a new
 * directory in the object hierarchy.
 */
static NTSTATUS ObpDirectoryObjectCreateProc(IN POBJECT Self,
					     IN PVOID CreaCtx)
{
    POBJECT_DIRECTORY Directory = (POBJECT_DIRECTORY) Self;
    assert(Self != NULL);

    for (int i = 0; i < OBP_DIROBJ_HASH_BUCKETS; i++) {
	InitializeListHead(&Directory->HashBuckets[i]);
    }
    return STATUS_SUCCESS;
}

/* Compute the hash index of the given string. */
static inline ULONG ObpDirectoryEntryHashIndex(IN PCSTR Str,
					       IN ULONG Length) /* Excluding trailing '\0' */
{
    ULONG Hash = RtlpHashStringEx(Str, Length);
    return Hash % OBP_DIROBJ_HASH_BUCKETS;
}

/* Looks up a named object under an object directory */
static NTSTATUS ObpLookupDirectoryEntry(IN POBJECT_DIRECTORY Directory,
					IN PCSTR Name,
					IN ULONG Length, /* Excluding trailing '\0' */
					OUT POBJECT *FoundObject)
{
    assert(Directory != NULL);
    assert(Name != NULL);
    assert(FoundObject != NULL);

    ULONG HashIndex = ObpDirectoryEntryHashIndex(Name, Length);
    assert(HashIndex < OBP_DIROBJ_HASH_BUCKETS);
    *FoundObject = NULL;
    LoopOverList(Entry, &Directory->HashBuckets[HashIndex],
		 OBJECT_DIRECTORY_ENTRY, ChainLink) {
	assert(Entry != NULL);
	assert(Entry->Name != NULL);
	if (strlen(Entry->Name) != Length) {
	    continue;
	}
	if (!strncmp(Name, Entry->Name, Length)) {
	    DbgTrace("Found object name = %s\n", Entry->Name);
	    *FoundObject = Entry->Object;
	}
    }

    if (*FoundObject == NULL) {
	return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    return STATUS_SUCCESS;
}

/*
 * Called when the Object Manager attempts to parse a path
 * under the object directory.
 */
static NTSTATUS ObpDirectoryObjectParseProc(IN POBJECT Self,
					    IN PCSTR Path,
					    IN POB_PARSE_CONTEXT ParseContext,
					    OUT POBJECT *FoundObject,
					    OUT PCSTR *RemainingPath)
{
    POBJECT_DIRECTORY Directory = (POBJECT_DIRECTORY) Self;
    DbgTrace("Trying to parse Path = %s\n", Path);
    assert(Self != NULL);
    assert(Path != NULL);
    assert(FoundObject != NULL);
    assert(RemainingPath != NULL);

    ULONG NameLength = ObpLocateFirstPathSeparator(Path);

    /* Look for the named object under the directory. */
    RET_ERR_EX(ObpLookupDirectoryEntry(Directory, Path, NameLength, FoundObject),
	       {
		   DbgTrace("Path %s not found\n", Path);
		   *FoundObject = NULL;
		   *RemainingPath = Path;
	       });
    *RemainingPath = Path + NameLength;
    /* The object manager will skip the leading OBJ_NAME_PATH_SEPARATOR */
    DbgTrace("Parse successful. RemainingPath = %s\n", *RemainingPath);
    return STATUS_SUCCESS;
}

/*
 * Called when the object manager attempts to insert an object
 * under the object directory
 */
static NTSTATUS ObpDirectoryObjectInsertProc(IN POBJECT Self,
					     IN POBJECT Object,
					     IN PCSTR Name)
{
    DbgTrace("Inserting name %s\n", Name);
    POBJECT_DIRECTORY Directory = (POBJECT_DIRECTORY) Self;
    assert(Self != NULL);
    assert(Name != NULL);
    assert(Object != NULL);

    /* Object name must not contain the OBJ_NAME_PATH_SEPARATOR */
    for (PCSTR Ptr = Name; *Ptr != '\0'; Ptr++) {
	if (*Ptr == OBJ_NAME_PATH_SEPARATOR) {
	    DbgTrace("Inserting name %s failed\n", Name);
	    return STATUS_OBJECT_PATH_SYNTAX_BAD;
	}
    }

    MWORD NameLength = strlen(Name);
    ObpAllocatePool(DirectoryEntry, OBJECT_DIRECTORY_ENTRY);
    ObpAllocatePoolEx(NameOwned, CHAR, NameLength+1, ExFreePool(DirectoryEntry));
    InitializeListHead(&DirectoryEntry->ChainLink);
    memcpy(NameOwned, Name, NameLength+1);
    DirectoryEntry->Name = NameOwned;
    DirectoryEntry->Object = Object;

    MWORD HashIndex = ObpDirectoryEntryHashIndex(Name, NameLength);
    assert(HashIndex < OBP_DIROBJ_HASH_BUCKETS);
    InsertHeadList(&Directory->HashBuckets[HashIndex], &DirectoryEntry->ChainLink);

    return STATUS_SUCCESS;
}

NTSTATUS ObpInitDirectoryObjectType()
{
    OBJECT_TYPE_INITIALIZER TypeInfo = {
	.CreateProc = ObpDirectoryObjectCreateProc,
	.ParseProc = ObpDirectoryObjectParseProc,
	.OpenProc = NULL,
	.InsertProc = ObpDirectoryObjectInsertProc,
    };
    return ObCreateObjectType(OBJECT_TYPE_DIRECTORY,
			      "Directory",
			      sizeof(OBJECT_DIRECTORY),
			      TypeInfo);
}

NTSTATUS ObCreateDirectory(IN PCSTR DirectoryPath)
{
    POBJECT_DIRECTORY Directory = NULL;
    RET_ERR(ObCreateObject(OBJECT_TYPE_DIRECTORY,
			   (POBJECT *) &Directory, NULL));
    assert(Directory != NULL);

    RET_ERR_EX(ObInsertObjectByPath(DirectoryPath, Directory),
	       ObDereferenceObject(Directory));

    return STATUS_SUCCESS;
}
