#include "obp.h"

POBJECT_DIRECTORY ObpRootObjectDirectory;

/*
 * Called when Executive components attempt to create a new
 * directory in the object hierarchy.
 */
static NTSTATUS ObpDirectoryObjectCreateProc(IN PVOID Self)
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
static NTSTATUS ObpDirectoryObjectOpenProc(IN PVOID Self)
{
    /* Do nothing. The object manager will assign a handle. */
    return STATUS_SUCCESS;
}

/* Compute the hash index of a given string. */
static ULONG ObpDirectoryEntryHashIndex(PCSTR Str)
{
    ULONG Hash = 5381;
    ULONG Chr;
    assert(Str != NULL);

    while ((Chr = (UCHAR) *Str++) != '\0') {
	assert(Chr < 256);
        Hash = ((Hash << 5) + Hash) + Chr; /* Hash * 33 + Chr */
    }

    return Hash % NUMBER_HASH_BUCKETS;
}

/* Looks up a named object under an object directory */
static NTSTATUS ObpLookupDirectoryEntry(IN POBJECT_DIRECTORY Directory,
					IN PCSTR Name,
					OUT POBJECT_HEADER *FoundObject)
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
static NTSTATUS ObpDirectoryObjectParseProc(IN PVOID Self,
					    IN PCSTR Path,
					    OUT POBJECT_HEADER *FoundObject,
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
	assert(FALSE);
	return STATUS_OBJECT_PATH_SYNTAX_BAD;
    }
    ObpAllocatePoolEx(Name, CHAR, NameLength+1, {});
    memcpy(Name, Path, NameLength);
    Name[NameLength] = '\0';

    /* Look for the named object under the directory. */
    NTSTATUS Status = ObpLookupDirectoryEntry(Directory, Name, FoundObject);
    ExFreePool(Name);

    if (!NT_SUCCESS(Status)) {
	*FoundObject = NULL;
	*RemainingPath = Path;
	return Status;
    }

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
static NTSTATUS ObpDirectoryObjectInsertProc(IN PVOID Self,
					     IN POBJECT_HEADER Object,
					     IN PCSTR Name)
{
    POBJECT_DIRECTORY Directory = (POBJECT_DIRECTORY) Self;
    assert(Self != NULL);
    assert(Name != NULL);
    assert(Object != NULL);

    /* Object name must not contain the OBJ_NAME_PATH_SEPARATOR */
    for (PCSTR Ptr = Name; *Ptr != '\0'; Ptr++) {
	if (*Ptr == OBJ_NAME_PATH_SEPARATOR) {
	    return STATUS_OBJECT_PATH_SYNTAX_BAD;
	}
    }

    ULONG BufferLength = strlen(Name)+1;
    ObpAllocatePool(DirectoryEntry, OBJECT_DIRECTORY_ENTRY);
    ObpAllocatePoolEx(NameOwned, CHAR, BufferLength, ExFreePool(DirectoryEntry));
    InitializeListHead(&DirectoryEntry->ChainLink);
    memcpy(NameOwned, Name, BufferLength);
    DirectoryEntry->Name = NameOwned;
    DirectoryEntry->Object = Object;

    ULONG HashIndex = ObpDirectoryEntryHashIndex(Name);
    assert(HashIndex < NUMBER_HASH_BUCKETS);
    InsertHeadList(&Directory->HashBuckets[HashIndex], &DirectoryEntry->ChainLink);

    return STATUS_SUCCESS;
}

NTSTATUS ObpInitDirectoryObjectType()
{
    OBJECT_TYPE_INITIALIZER TypeInfo = {
	.CreateProc = ObpDirectoryObjectCreateProc,
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
			     OUT POBJECT_HEADER *FoundObject)
{
    assert(ObpRootObjectDirectory != NULL);
    assert(Path != NULL);
    assert(FoundObject != NULL);
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

    /* Recursively invoke the parse method of the object,
     * until either the remaining path is empty, or the parse
     * method fails. */
    PVOID Object = ObpRootObjectDirectory;
    NTSTATUS Status = STATUS_SUCCESS;

    while (TRUE) {
	POBJECT_HEADER ObjectHeader = OBJECT_TO_OBJECT_HEADER(Object);
	POBJECT_HEADER Subobject = NULL;
	PCSTR RemainingPath = Path;
	Status = ObjectHeader->Type->TypeInfo.ParseProc(Object,
							Path,
							&Subobject,
							&RemainingPath);
	if (!NT_SUCCESS(Status)) {
	    return STATUS_OBJECT_NAME_NOT_FOUND;
	}
	/* It is a programming error if Subobject is NULL */
	assert(Subobject != NULL);
	/* Remaining path should not have leading OBJ_NAME_PATH_SEPARATOR */
	if (*RemainingPath == OBJ_NAME_PATH_SEPARATOR) {
	    assert(FASLE);
	    RemainingPath++;
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
	Object = OBJECT_HEADER_TO_OBJECT(Subobject);
	Path = RemainingPath;
    }
}
