#include "obp.h"

#define OBP_DIROBJ_HASH_BUCKETS 37
typedef struct _OBJECT_DIRECTORY {
    LIST_ENTRY HashBuckets[OBP_DIROBJ_HASH_BUCKETS];
    PIO_FILE_OBJECT FileObject;
} OBJECT_DIRECTORY;

typedef struct _OBJECT_DIRECTORY_ENTRY {
    LIST_ENTRY ChainLink;
    POBJECT Object;
    PCSTR ObjectName;
    POBJECT_DIRECTORY Parent;
} OBJECT_DIRECTORY_ENTRY, *POBJECT_DIRECTORY_ENTRY;

POBJECT_DIRECTORY ObpRootObjectDirectory;

/*
 * Called when Executive components attempt to create a new
 * directory in the object hierarchy.
 */
static NTSTATUS ObpDirectoryObjectCreateProc(IN POBJECT Self,
					     IN PVOID CreaCtx)
{
    POBJECT_DIRECTORY Directory = (POBJECT_DIRECTORY)Self;
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
					IN BOOLEAN CaseInsensitive,
					OUT POBJECT *FoundObject,
					OUT OPTIONAL POBJECT_DIRECTORY_ENTRY *DirectoryEntry)
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
	assert(Entry->Object != NULL);
	ObDbg("Checking object %s\n", Entry->ObjectName);
	if (strlen(Entry->ObjectName) != Length) {
	    continue;
	}
	INT (*Comparer)(PCSTR, PCSTR, ULONG_PTR) = CaseInsensitive ? _strnicmp : strncmp;
	if (!Comparer(Name, Entry->ObjectName, Length)) {
	    ObDbg("Found object name = %s\n", Entry->ObjectName);
	    *FoundObject = Entry->Object;
	    if (DirectoryEntry != NULL) {
		*DirectoryEntry = Entry;
	    }
	}
    }

    if (*FoundObject == NULL) {
	return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    return STATUS_SUCCESS;
}

NTSTATUS ObDirectoryObjectSearchObject(IN POBJECT_DIRECTORY Directory,
				       IN PCSTR Name,
				       IN ULONG Length, /* Excluding trailing '\0' */
				       IN BOOLEAN CaseInsensitive,
				       OUT POBJECT *FoundObject)
{
    return ObpLookupDirectoryEntry(Directory, Name, Length, CaseInsensitive,
				   FoundObject, NULL);
}

/*
 * Called when the Object Manager attempts to parse a path
 * under the object directory.
 */
static NTSTATUS ObpDirectoryObjectParseProc(IN POBJECT Self,
					    IN PCSTR Path,
					    IN BOOLEAN CaseInsensitive,
					    OUT POBJECT *FoundObject,
					    OUT PCSTR *RemainingPath)
{
    POBJECT_DIRECTORY Directory = (POBJECT_DIRECTORY)Self;
    ObDbg("Trying to parse Path = %s case-%s\n", Path,
	  CaseInsensitive ? "insensitively" : "sensitively");
    assert(Self != NULL);
    assert(Path != NULL);
    assert(FoundObject != NULL);
    assert(RemainingPath != NULL);
    *RemainingPath = Path;

    /* Skip the leading path separator. */
    if (Path[0] == OBJ_NAME_PATH_SEPARATOR) {
	Path++;
    }

    /* If the Path is empty, stop parsing. */
    if (Path[0] == '\0') {
	return STATUS_NTOS_STOP_PARSING;
    }

    ULONG NameLength = ObLocateFirstPathSeparator(Path);
    if (NameLength == 0) {
	return STATUS_OBJECT_NAME_INVALID;
    }

    /* Look for the named object under the directory. */
    RET_ERR_EX(ObDirectoryObjectSearchObject(Directory, Path, NameLength,
					     CaseInsensitive, FoundObject),
	       {
		   ObDbg("Path %s not found\n", Path);
		   *FoundObject = NULL;
	       });
    *RemainingPath = Path + NameLength;
    ObDbg("Parse successful. RemainingPath = %s\n", *RemainingPath);
    return STATUS_SUCCESS;
}

static NTSTATUS IopDirectoryObjectOpenProc(IN ASYNC_STATE State,
					   IN PTHREAD Thread,
					   IN POBJECT Object,
					   IN PCSTR SubPath,
					   IN ACCESS_MASK DesiredAccess,
					   IN ULONG Attributes,
					   IN POB_OPEN_CONTEXT OpenContext,
					   OUT POBJECT *pOpenedInstance,
					   OUT PCSTR *pRemainingPath)
{
    assert(Thread != NULL);
    assert(Object != NULL);
    assert(SubPath != NULL);
    assert(pOpenedInstance != NULL);
    assert(ObObjectIsType(Object, OBJECT_TYPE_DIRECTORY));

    *pRemainingPath = SubPath;
    /* Skip the leading path separator. */
    if (SubPath[0] == OBJ_NAME_PATH_SEPARATOR) {
	SubPath++;
    }
    if (*SubPath != '\0') {
	return STATUS_OBJECT_NAME_INVALID;
    }
    POBJECT_DIRECTORY DirObj = Object;
    if (OpenContext->Type == OPEN_CONTEXT_DEVICE_OPEN) {
	/* If we are opening an object directory as a file, look for the file
	 * object with name ".". This is so in the very early stage of the boot
	 * ntdll can open a file handle to the boot modules directory. */
	RET_ERR(ObDirectoryObjectSearchObject(DirObj, ".", 1,
					      FALSE, pOpenedInstance));
	ObpReferenceObject(*pOpenedInstance);
	*pRemainingPath = SubPath;
    } else {
	/* TODO: Implement NtOpenObjectDirectory */
	UNIMPLEMENTED;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS ObpDirectoryObjectCloseProc(IN ASYNC_STATE State,
					    IN PTHREAD Thread,
					    IN POBJECT Object)
{
    /* TODO: Implement NtOpenObjectDirectory */
    return STATUS_SUCCESS;
}

static NTSTATUS ObpDirectoryObjectInsertObject(IN POBJECT_DIRECTORY Directory,
					       IN POBJECT Object,
					       IN PCSTR Name,
					       IN ULONG NameLength)
{
    ObDbg("Inserting object %p name %s (len 0x%x) into directory %p\n",
	  Object, Name, NameLength, Directory);
    /* Object name must not be empty. */
    assert(Name[0]);
    /* Object name must not contain the OBJ_NAME_PATH_SEPARATOR */
    for (ULONG i = 0; i < NameLength; i++) {
	if (Name[i] == OBJ_NAME_PATH_SEPARATOR) {
	    assert(FALSE);
	    return STATUS_OBJECT_PATH_INVALID;
	}
    }

    PCHAR ObjectName = RtlDuplicateStringEx(Name, NameLength, NTOS_OB_TAG);
    if (!ObjectName) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    ObpAllocatePoolEx(DirectoryEntry, OBJECT_DIRECTORY_ENTRY,
		      sizeof(OBJECT_DIRECTORY_ENTRY), ObpFreePool(ObjectName));
    DirectoryEntry->Object = Object;
    DirectoryEntry->ObjectName = ObjectName;
    DirectoryEntry->Parent = Directory;
    OBJECT_TO_OBJECT_HEADER(Object)->ParentLink = DirectoryEntry;

    MWORD HashIndex = ObpDirectoryEntryHashIndex(Name, NameLength);
    assert(HashIndex < OBP_DIROBJ_HASH_BUCKETS);
    InsertHeadList(&Directory->HashBuckets[HashIndex], &DirectoryEntry->ChainLink);
    return STATUS_SUCCESS;
}

NTSTATUS ObDirectoryObjectInsertObject(IN POBJECT_DIRECTORY Directory,
				       IN POBJECT Object,
				       IN PCSTR Name)
{
    return ObpDirectoryObjectInsertObject(Directory, Object, Name, strlen(Name));
}

/*
 * Called when the object manager attempts to insert an object
 * under the object directory
 */
static NTSTATUS ObpDirectoryObjectInsertProc(IN POBJECT Self,
					     IN POBJECT Object,
					     IN PCSTR Name)
{
    ObDbg("Inserting name %s\n", Name);
    POBJECT_DIRECTORY Directory = (POBJECT_DIRECTORY) Self;
    assert(Self != NULL);
    assert(Name != NULL);
    assert(Object != NULL);

    return ObDirectoryObjectInsertObject(Directory, Object, Name);
}

VOID ObDirectoryObjectRemoveObject(IN POBJECT Subobject)
{
    POBJECT_HEADER ObjectHeader = OBJECT_TO_OBJECT_HEADER(Subobject);
    POBJECT_DIRECTORY_ENTRY Entry = ObjectHeader->ParentLink;
    assert(Entry != NULL);
    assert(Entry->Object == Subobject);
    RemoveEntryList(&Entry->ChainLink);
    assert(Entry->ObjectName);
    ObpFreePool(Entry->ObjectName);
    ObpFreePool(Entry);
    ObjectHeader->ParentLink = NULL;
}

/*
 * Called when the object manager attempts to remove an object
 * under the object directory
 */
static VOID ObpDirectoryObjectRemoveProc(IN POBJECT Subobject)
{
    ObDirectoryObjectRemoveObject(Subobject);
}

/*
 * Called when the object manager attempts to delete the object
 * directory
 */
static VOID ObpDirectoryObjectDeleteProc(IN POBJECT Self)
{
    assert(ObObjectIsType(Self, OBJECT_TYPE_DIRECTORY));
    UNUSED POBJECT_DIRECTORY Directory = (POBJECT_DIRECTORY)Self;
    /* Object directory should be empty at this point. We assert if this
     * has not been maintained. */
    assert(!ObDirectoryGetObjectCount(Directory));
    /* We don't need to free the directory object here since
     * the object manager does that for us */
}

NTSTATUS ObpInitDirectoryObjectType()
{
    OBJECT_TYPE_INITIALIZER TypeInfo = {
	.CreateProc = ObpDirectoryObjectCreateProc,
	.ParseProc = ObpDirectoryObjectParseProc,
	.OpenProc = IopDirectoryObjectOpenProc,
	.CloseProc = ObpDirectoryObjectCloseProc,
	.InsertProc = ObpDirectoryObjectInsertProc,
	.RemoveProc = ObpDirectoryObjectRemoveProc,
	.DeleteProc = ObpDirectoryObjectDeleteProc,
    };
    return ObCreateObjectType(OBJECT_TYPE_DIRECTORY,
			      "Directory",
			      sizeof(OBJECT_DIRECTORY),
			      TypeInfo);
}

NTSTATUS ObCreateDirectoryEx(IN OPTIONAL POBJECT Parent,
			     IN PCSTR DirectoryPath,
			     OUT OPTIONAL POBJECT_DIRECTORY *DirObj)
{
    POBJECT_DIRECTORY Directory = NULL;
    RET_ERR(ObCreateObject(OBJECT_TYPE_DIRECTORY, (POBJECT *)&Directory, NULL));
    assert(Directory != NULL);
    RET_ERR_EX(ObInsertObject(Parent, Directory, DirectoryPath, 0),
	       ObDereferenceObject(Directory));
    if (DirObj) {
	*DirObj = Directory;
    }
    return STATUS_SUCCESS;
}

NTSTATUS ObCreateParentDirectory(IN OPTIONAL POBJECT RootDirectory,
				 IN PCSTR ObjectPath,
				 OUT OPTIONAL POBJECT_DIRECTORY *ParentDir)
{
    /* Parse the object path against the root directory until failure. */
    POBJECT ParentObj = NULL;
    PCSTR ObjectName = NULL, StringToFree = NULL;
    NTSTATUS Status = ObpParseObjectByName(RootDirectory, ObjectPath, FALSE,
					   &ParentObj, &ObjectName, &StringToFree);
    if (!ParentObj || !ObObjectIsType(ParentObj, OBJECT_TYPE_DIRECTORY)) {
	Status = STATUS_OBJECT_NAME_INVALID;
	goto out;
    }
    Status = STATUS_SUCCESS;
    ULONG Sep = ObLocateFirstPathSeparator(ObjectName);
    while (Sep && ObjectName[Sep] == OBJ_NAME_PATH_SEPARATOR && ObjectName[Sep+1]) {
	POBJECT_DIRECTORY DirObj = NULL;
	Status = ObCreateObject(OBJECT_TYPE_DIRECTORY, (POBJECT *)&DirObj, NULL);
	if (!NT_SUCCESS(Status)) {
	    break;
	}
	Status = ObpDirectoryObjectInsertObject(ParentObj, DirObj, ObjectName, Sep);
	if (!NT_SUCCESS(Status)) {
	    break;
	}
	ObjectName += Sep + 1;
	ParentObj = DirObj;
	Sep = ObLocateFirstPathSeparator(ObjectName);
    }
    assert(ParentObj && ObObjectIsType(ParentObj, OBJECT_TYPE_DIRECTORY));
    *ParentDir = ParentObj;
out:
    if (StringToFree) {
	ExFreePoolWithTag(StringToFree, OB_PARSE_TAG);
    }
    return Status;
}

POBJECT_DIRECTORY ObGetParentDirectory(IN POBJECT Object)
{
    assert(Object);
    POBJECT_HEADER ObjectHeader = OBJECT_TO_OBJECT_HEADER(Object);
    POBJECT_DIRECTORY_ENTRY Entry = ObjectHeader->ParentLink;
    return Entry ? Entry->Parent : NULL;
}

/* Return the number of subobjects in a directory object */
SIZE_T ObDirectoryGetObjectCount(IN POBJECT_DIRECTORY DirObj)
{
    SIZE_T ObjectCount = 0;
    for (int i = 0; i < OBP_DIROBJ_HASH_BUCKETS; i++) {
	ObjectCount += GetListLength(&DirObj->HashBuckets[i]);
    }
    return ObjectCount;
}
