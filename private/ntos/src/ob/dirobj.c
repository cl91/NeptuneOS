#include "obp.h"

POBJECT_DIRECTORY ObpRootObjectDirectory;

/*
 * Called when Executive components attempt to create a new
 * directory in the object hierarchy.
 */
static NTSTATUS ObpDirectoryObjectInitProc(IN POBJECT Self)
{
    POBJECT_DIRECTORY Directory = (POBJECT_DIRECTORY) Self;
    assert(Self != NULL);

    for (int i = 0; i < NUMBER_HASH_BUCKETS; i++) {
	InitializeListHead(&Directory->HashBuckets[i]);
    }
    return STATUS_SUCCESS;
}

/*
 * Called when a client process attempts to open an object
 * directory in the object hierarchy.
 */
static NTSTATUS ObpDirectoryObjectOpenProc(IN POBJECT Self)
{
    /* Do nothing. The object manager will assign a handle. */
    return STATUS_SUCCESS;
}

/* Compute the hash index of a given string. */
static ULONG ObpDirectoryEntryHashIndex(PCSTR Str)
{
    ULONG Hash = RtlpHashString(Str);
    return Hash % NUMBER_HASH_BUCKETS;
}

/* Looks up a named object under an object directory */
static NTSTATUS ObpLookupDirectoryEntry(IN POBJECT_DIRECTORY Directory,
					IN PCSTR Name,
					OUT POBJECT *FoundObject)
{
    assert(Directory != NULL);
    assert(Name != NULL);
    assert(FoundObject != NULL);

    /* The object name should never contain OBJ_NAME_PATH_SEPARATOR.
     * The object manager guarantees this, so only check on debug build.
     */
    for (PCSTR Ptr = Name; *Ptr != '\0'; Ptr++) {
	assert(*Ptr != OBJ_NAME_PATH_SEPARATOR);
    }

    ULONG HashIndex = ObpDirectoryEntryHashIndex(Name);
    assert(HashIndex < NUMBER_HASH_BUCKETS);
    *FoundObject = NULL;
    LoopOverList(Entry, &Directory->HashBuckets[HashIndex],
		 OBJECT_DIRECTORY_ENTRY, ChainLink) {
	assert(Entry != NULL);
	assert(Entry->Name != NULL);
	if (!strcmp(Name, Entry->Name)) {
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
					    OUT POBJECT *FoundObject,
					    OUT PCSTR *RemainingPath)
{
    POBJECT_DIRECTORY Directory = (POBJECT_DIRECTORY) Self;
    assert(Self != NULL);
    assert(Path != NULL);
    assert(FoundObject != NULL);
    assert(RemainingPath != NULL);

    /* Extract the name of the sub-object, which will be whatever is
     * before the first OBJ_NAME_PATH_SEPARATOR. The remaining path will be
     * whatever is left after the first OBJ_NAME_PATH_SEPARATOR (possibly empty).
     */
    MWORD NameLength = 0;
    for (PCSTR Ptr = Path; (*Ptr != '\0') && (*Ptr != OBJ_NAME_PATH_SEPARATOR); Ptr++)
	NameLength++;
    if (NameLength == 0) {
	/* This is a programming error since the object manager shall always
	 * call the parse method without the leading OBJ_NAME_PATH_SEPARATOR.
	 */
	return STATUS_NTOS_BUG;
    }
    ObpAllocatePoolEx(Name, CHAR, NameLength+1, {});
    memcpy(Name, Path, NameLength);
    Name[NameLength] = '\0';

    /* Look for the named object under the directory. */
    RET_ERR_EX(ObpLookupDirectoryEntry(Directory, Name, FoundObject),
	       {
		   ExFreePool(Name);
		   *FoundObject = NULL;
		   *RemainingPath = Path;
	       });
    ExFreePool(Name);
    *RemainingPath = Path + NameLength;

    /* Remaining path does not include leading OBJ_NAME_PATH_SEPARATOR */
    if (**RemainingPath == OBJ_NAME_PATH_SEPARATOR) {
	(*RemainingPath)++;
    }
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

    MWORD BufferLength = strlen(Name)+1;
    ObpAllocatePool(DirectoryEntry, OBJECT_DIRECTORY_ENTRY);
    ObpAllocatePoolEx(NameOwned, CHAR, BufferLength, ExFreePool(DirectoryEntry));
    InitializeListHead(&DirectoryEntry->ChainLink);
    memcpy(NameOwned, Name, BufferLength);
    DirectoryEntry->Name = NameOwned;
    DirectoryEntry->Object = Object;

    MWORD HashIndex = ObpDirectoryEntryHashIndex(Name);
    assert(HashIndex < NUMBER_HASH_BUCKETS);
    InsertHeadList(&Directory->HashBuckets[HashIndex], &DirectoryEntry->ChainLink);

    return STATUS_SUCCESS;
}

NTSTATUS ObpInitDirectoryObjectType()
{
    OBJECT_TYPE_INITIALIZER TypeInfo = {
	.InitProc = ObpDirectoryObjectInitProc,
	.OpenProc = ObpDirectoryObjectOpenProc,
	.ParseProc = ObpDirectoryObjectParseProc,
	.InsertProc = ObpDirectoryObjectInsertProc,
    };
    return ObCreateObjectType(OBJECT_TYPE_DIRECTORY,
			      "Directory",
			      sizeof(OBJECT_DIRECTORY),
			      TypeInfo);
}

/*
 * Parse the object path recursively and return the final object
 * to which the path points.
 */
NTSTATUS ObpLookupObjectName(IN PCSTR Path,
			     OUT POBJECT *FoundObject)
{
    assert(ObpRootObjectDirectory != NULL);
    assert(Path != NULL);
    assert(FoundObject != NULL);

    if (Path[0] == '\0') {
	return STATUS_OBJECT_PATH_SYNTAX_BAD;
    }

    /* Points to the terminating '\0' charactor of Path */
    PCSTR LastByte = Path + strlen(Path);

    /* Skip the leading OBJ_NAME_PATH_SEPARATOR. We always
     * start the lookup from the root directory. Normally user should
     * specify all paths with a leading OBJ_NAME_PATH_SEPARATOR,
     * but if a relative path is supplied, the root directory
     * is understood to be the starting point of the lookup.
     */
    if (*Path == OBJ_NAME_PATH_SEPARATOR) {
	Path++;
    }

    /* Caller has simply requested the root directory. */
    if (Path[0] == '\0') {
	*FoundObject = ObpRootObjectDirectory;
	return STATUS_SUCCESS;
    }

    /* Recursively invoke the parse method of the object,
     * until either the remaining path is empty, or the parse
     * method fails. */
    POBJECT Object = ObpRootObjectDirectory;
    NTSTATUS Status = STATUS_SUCCESS;

    while (TRUE) {
	POBJECT_HEADER ObjectHeader = OBJECT_TO_OBJECT_HEADER(Object);
	POBJECT Subobject = NULL;
	PCSTR RemainingPath = Path;
	OBJECT_PARSE_METHOD ParseProc = ObjectHeader->Type->TypeInfo.ParseProc;
	if (ParseProc == NULL) {
	    return STATUS_OBJECT_NAME_NOT_FOUND;
	}
	RET_ERR(ParseProc(Object, Path, &Subobject, &RemainingPath));
	/* It is a programming error if Subobject is NULL */
	if (Subobject == NULL) {
	    return STATUS_NTOS_BUG;
	}
	/* Remaining path should not have leading OBJ_NAME_PATH_SEPARATOR */
	if (*RemainingPath == OBJ_NAME_PATH_SEPARATOR) {
	    return STATUS_NTOS_BUG;
	}
	/* Remaining path should also be within the original Path */
	assert(RemainingPath > Path);
	assert(RemainingPath <= LastByte);
	/* If remaining path is empty, we are done. */
	if (*RemainingPath == '\0') {
	    *FoundObject = Subobject;
	    return STATUS_SUCCESS;
	}
	/* Else, we keep parsing */
	Object = Subobject;
	Path = RemainingPath;
    }
}

NTSTATUS ObCreateDirectory(IN PCSTR DirectoryPath)
{
    POBJECT_DIRECTORY Directory = NULL;
    RET_ERR(ObCreateObject(OBJECT_TYPE_DIRECTORY,
			   (POBJECT *) &Directory));
    assert(Directory != NULL);

    RET_ERR_EX(ObInsertObjectByPath(DirectoryPath, Directory),
	       ObDeleteObject(Directory));

    return STATUS_SUCCESS;
}
