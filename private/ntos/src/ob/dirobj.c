#include "ob.h"
#include "obp.h"

#define OBP_DIROBJ_HASH_BUCKETS 37
typedef struct _OBJECT_DIRECTORY {
    LIST_ENTRY HashBuckets[OBP_DIROBJ_HASH_BUCKETS];
    PIO_FILE_OBJECT FileObject;
} OBJECT_DIRECTORY;

typedef struct _OBJECT_DIRECTORY_ENTRY {
    LIST_ENTRY ChainLink;
    POBJECT Object;
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
	ObDbg("Checking object %s\n", ObGetObjectName(Entry->Object));
	if (strlen(ObGetObjectName(Entry->Object)) != Length) {
	    continue;
	}
	INT (*Comparer)(PCSTR, PCSTR, ULONG_PTR) = CaseInsensitive ? _strnicmp : strncmp;
	if (!Comparer(Name, ObGetObjectName(Entry->Object), Length)) {
	    ObDbg("Found object name = %s\n", ObGetObjectName(Entry->Object));
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

    ULONG NameLength = ObpLocateFirstPathSeparator(Path);
    if (NameLength == 0) {
	return STATUS_OBJECT_NAME_INVALID;
    }

    /* Look for the named object under the directory. */
    RET_ERR_EX(ObpLookupDirectoryEntry(Directory, Path, NameLength,
				       CaseInsensitive, FoundObject, NULL),
	       {
		   ObDbg("Path %s not found\n", Path);
		   *FoundObject = NULL;
		   *RemainingPath = Path;
	       });
    *RemainingPath = Path + NameLength;
    /* The object manager will skip the leading OBJ_NAME_PATH_SEPARATOR */
    ObDbg("Parse successful. RemainingPath = %s\n", *RemainingPath);
    return STATUS_SUCCESS;
}

static NTSTATUS IopDirectoryObjectOpenProc(IN ASYNC_STATE State,
					   IN PTHREAD Thread,
					   IN POBJECT Object,
					   IN PCSTR SubPath,
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
    if (*SubPath != '\0') {
	return STATUS_OBJECT_NAME_INVALID;
    }
    POBJECT_DIRECTORY DirObj = Object;
    if (!DirObj->FileObject) {
	RET_ERR(IoCreateDevicelessFile(NULL, NULL, 0, &DirObj->FileObject));
    }
    *pOpenedInstance = DirObj->FileObject;
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
    ObDbg("Inserting name %s\n", Name);
    POBJECT_DIRECTORY Directory = (POBJECT_DIRECTORY) Self;
    assert(Self != NULL);
    assert(Name != NULL);
    assert(Object != NULL);

    /* Object name must not contain the OBJ_NAME_PATH_SEPARATOR */
    for (PCSTR Ptr = Name; *Ptr != '\0'; Ptr++) {
	if (*Ptr == OBJ_NAME_PATH_SEPARATOR) {
	    ObDbg("Inserting name %s failed\n", Name);
	    /* This usually means that the user did not create the intermediate
	     * directory object. We return OBJECT_NAME_NOT_FOUND in this case. */
	    return STATUS_OBJECT_NAME_NOT_FOUND;
	}
    }

    ObpAllocatePool(DirectoryEntry, OBJECT_DIRECTORY_ENTRY);
    DirectoryEntry->Object = Object;
    ObpReferenceObject(Object);
    OBJECT_TO_OBJECT_HEADER(Object)->ParentLink = DirectoryEntry;

    MWORD HashIndex = ObpDirectoryEntryHashIndex(Name, strlen(Name));
    assert(HashIndex < OBP_DIROBJ_HASH_BUCKETS);
    InsertHeadList(&Directory->HashBuckets[HashIndex], &DirectoryEntry->ChainLink);

    return STATUS_SUCCESS;
}

static inline VOID ObpObjectDirectoryRemoveEntry(IN POBJECT_DIRECTORY_ENTRY Entry)
{
    if (Entry != NULL) {
	ObDereferenceObject(Entry->Object);
	RemoveEntryList(&Entry->ChainLink);
	ObpFreePool(Entry);
    }
}

/*
 * Called when the object manager attempts to remove an object
 * under the object directory
 */
static VOID ObpDirectoryObjectRemoveProc(IN POBJECT Subobject)
{
    POBJECT_HEADER ObjectHeader = OBJECT_TO_OBJECT_HEADER(Subobject);
    assert(ObObjectIsType(ObjectHeader->ParentObject, OBJECT_TYPE_DIRECTORY));
    POBJECT_DIRECTORY_ENTRY Entry = ObjectHeader->ParentLink;
    assert(Entry != NULL);
    assert(Entry->Object == Subobject);
    ObpObjectDirectoryRemoveEntry(Entry);
}

/*
 * Called when the object manager attempts to delete the object
 * directory
 */
static VOID ObpDirectoryObjectDeleteProc(IN POBJECT Self)
{
    assert(ObObjectIsType(Self, OBJECT_TYPE_DIRECTORY));
    POBJECT_DIRECTORY Directory = (POBJECT_DIRECTORY)Self;
    /* For each object in this object directory we unlink them
     * from the object directory. */
    for (ULONG i = 0; i < OBP_DIROBJ_HASH_BUCKETS; i++) {
        LoopOverList(Entry, &Directory->HashBuckets[i],
		     OBJECT_DIRECTORY_ENTRY, ChainLink) {
	    ObpObjectDirectoryRemoveEntry(Entry);
	}
    }
    /* We don't need to free the directory object here since
     * the object manager does that for us */
}

NTSTATUS ObpInitDirectoryObjectType()
{
    OBJECT_TYPE_INITIALIZER TypeInfo = {
	.CreateProc = ObpDirectoryObjectCreateProc,
	.ParseProc = ObpDirectoryObjectParseProc,
	.OpenProc = IopDirectoryObjectOpenProc,
	.InsertProc = ObpDirectoryObjectInsertProc,
	.RemoveProc = ObpDirectoryObjectRemoveProc,
	.DeleteProc = ObpDirectoryObjectDeleteProc,
    };
    return ObCreateObjectType(OBJECT_TYPE_DIRECTORY,
			      "Directory",
			      sizeof(OBJECT_DIRECTORY),
			      TypeInfo);
}

NTSTATUS ObCreateDirectory(IN PCSTR DirectoryPath)
{
    POBJECT_DIRECTORY Directory = NULL;
    RET_ERR(ObCreateObject(OBJECT_TYPE_DIRECTORY, (POBJECT *)&Directory, NULL));
    assert(Directory != NULL);
    RET_ERR_EX(ObInsertObject(NULL, Directory, DirectoryPath, 0),
	       ObDereferenceObject(Directory));
    return STATUS_SUCCESS;
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
