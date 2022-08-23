#pragma once

/* Comment this to enable debug tracing on debug build */
/* #ifndef NDEBUG */
/* #define NDEBUG */
/* #endif */

#include <ntos.h>

#define NTOS_CM_TAG	(EX_POOL_TAG('n','t','c','m'))

#define CmpAllocatePoolEx(Var, Type, Size, OnError)		\
    ExAllocatePoolEx(Var, Type, Size, NTOS_CM_TAG, OnError)

#define CmpAllocateObject(Var, Type)				\
    CmpAllocatePoolEx(Var, Type, sizeof(Type), {})

#define CmpFreePool(Var) ExFreePoolWithTag(Var, NTOS_CM_TAG)

typedef enum _CM_NODE_TYPE {
    CM_NODE_KEY,
    CM_NODE_VALUE
} CM_NODE_TYPE;

/*
 * Hash table entry for a registry node (ie. key or value)
 *
 * This is the base object (in the OOP-sense) for CM_KEY_OBJECT and
 * CM_REG_VALUE.
 */
typedef struct _CM_NODE {
    LIST_ENTRY HashLink;
    struct _CM_KEY_OBJECT *Parent;
    CM_NODE_TYPE Type;
} CM_NODE, *PCM_NODE;

/* For now this is set as a fixed number. Eventually we will want to
 * dynamically expand the registry key hashes since some registry keys
 * have a very large number of values or sub-keys. */
#define CM_KEY_HASH_BUCKETS	37

/*
 * Registry Key object. This is the object body of OBJECT_TYPE_KEY.
 */
typedef struct _CM_KEY_OBJECT {
    CM_NODE Node; /* Hash-table entry for the parent key. Must be first */
    LIST_ENTRY HashBuckets[CM_KEY_HASH_BUCKETS];
    LIST_ENTRY SubKeyList;
    LIST_ENTRY SubKeyListEntry;	/* List entry of parent's SubKeyList */
    LARGE_INTEGER LastWriteTime;
    PVOID ClassData;
    ULONG ClassLength;
    ULONG MaxNameLength;	/* Does NOT include trailing NUL. Same below. */
    ULONG MaxUtf16NameLength;
    ULONG MaxClassLength;
    ULONG MaxValueNameLength;
    ULONG MaxUtf16ValueNameLength;
    ULONG MaxValueDataLength;
    ULONG MaxUtf16ValueDataLength;
    ULONG StableSubKeyCount;
    ULONG VolatileSubKeyCount;
    ULONG ValueCount;
    ULONG UserFlags;
    BOOLEAN Volatile;
} CM_KEY_OBJECT, *PCM_KEY_OBJECT;

/* Compute the hash index of the given string. */
static inline ULONG CmpKeyHashIndex(IN PCSTR Str)
{
    ULONG Hash = RtlpHashString(Str);
    return Hash % CM_KEY_HASH_BUCKETS;
}

/*
 * Compute the hash index of the given string up to the given length.
 *
 * The length does not include the trailing '\0'.
 */
static inline ULONG CmpKeyHashIndexEx(IN PCSTR Str,
				      IN ULONG Length)
{
    ULONG Hash = RtlpHashStringEx(Str, Length);
    return Hash % CM_KEY_HASH_BUCKETS;
}

/*
 * Registry value
 */
typedef struct _CM_REG_VALUE {
    CM_NODE Node; /* Hash-table entry for the parent key. Must be first */
    PCSTR Name;	  /* Allocated on the ExPool. Owned by this object */
    ULONG Type;	  /* REG_NONE, REG_SZ, etc */
    ULONG NameLength;	   /* Does NOT include trailing NUL */
    ULONG Utf16NameLength; /* Does NOT include training UNICODE NUL */
    union {
	ULONG Dword;
	ULONGLONG Qword;
	struct {
	    PVOID Data;		/* Must be first in this struct */
	    ULONG DataSize;
	    ULONG Utf16DataSize; /* Size of the string data if it were converted
				  * into UTF16. Same as DataSize if not string. */
	};
    };
} CM_REG_VALUE, *PCM_REG_VALUE;

static inline PCM_NODE CmpGetNamedNode(IN PCM_KEY_OBJECT Key,
				       IN PCSTR Name,
				       IN OPTIONAL ULONG NameLength)
{
    if (NameLength == 0) {
	NameLength = strlen(Name);
    }
    ULONG HashIndex = CmpKeyHashIndexEx(Name, NameLength);
    assert(HashIndex < CM_KEY_HASH_BUCKETS);

    PCM_NODE NodeFound = NULL;
    LoopOverList(Node, &Key->HashBuckets[HashIndex], CM_NODE, HashLink) {
	assert(Node->Type == CM_NODE_KEY || Node->Type == CM_NODE_VALUE);
	PCSTR NodeName = Node->Type == CM_NODE_KEY ?
	    ObGetObjectName(Node) : ((PCM_REG_VALUE)Node)->Name;
	if (!_strnicmp(Name, NodeName, NameLength)) {
	    NodeFound = Node;
	}
    }
    return NodeFound;
}

static inline ULONG CmpGetValueDataLength(IN PCM_REG_VALUE Value,
					  IN BOOLEAN Utf16)
{
    assert(Value != NULL);
    if (Value->Type == REG_DWORD || Value->Type == REG_DWORD_BIG_ENDIAN) {
	return sizeof(ULONG);
    } else if (Value->Type == REG_QWORD) {
	return sizeof(ULONGLONG);
    } else if (Value->Type == REG_NONE) {
	return 0;
    } else {
	return Utf16 ? Value->Utf16DataSize : Value->DataSize;
    }
}

/*
 * Link the node to parent.
 */
static inline VOID CmpInsertNamedNode(IN PCM_KEY_OBJECT Parent,
				      IN PCM_NODE Node,
				      IN PCSTR NodeName)
{
    assert(Parent != NULL);
    assert(ObObjectIsType(Parent, OBJECT_TYPE_KEY));
    assert(Parent->Node.Type == CM_NODE_KEY);
    Node->Parent = Parent;
    ULONG HashIndex = CmpKeyHashIndex(NodeName);
    InsertTailList(&Parent->HashBuckets[HashIndex], &Node->HashLink);
    ULONG NameLen = strlen(NodeName);
    ULONG Utf16NameLen = 0;
    RtlUTF8ToUnicodeN(NULL, 0, &Utf16NameLen, NodeName, NameLen);
    if (Utf16NameLen < NameLen * sizeof(WCHAR)) {
	Utf16NameLen = NameLen * sizeof(WCHAR);
    }
    if (NameLen > Parent->MaxNameLength) {
	Parent->MaxNameLength = NameLen;
    }
    if (Utf16NameLen > Parent->MaxUtf16NameLength) {
	Parent->MaxUtf16NameLength = Utf16NameLen;
    }
    if (Node->Type == CM_NODE_KEY) {
	PCM_KEY_OBJECT Key = (PCM_KEY_OBJECT)Node;
	if (Key->Volatile) {
	    Parent->VolatileSubKeyCount++;
	} else {
	    Parent->StableSubKeyCount++;
	}
	if (Key->ClassLength > Parent->MaxClassLength) {
	    Parent->MaxClassLength = Key->ClassLength;
	}
    } else {
	assert(Node->Type == CM_NODE_VALUE);
	Parent->ValueCount++;
	PCM_REG_VALUE Value = (PCM_REG_VALUE)Node;
	Value->NameLength = NameLen;
	Value->Utf16NameLength = Utf16NameLen;
	ULONG ValueDataLen = CmpGetValueDataLength(Value, FALSE);
	ULONG Utf16ValueDataLen = CmpGetValueDataLength(Value, TRUE);
	if (NameLen > Parent->MaxValueNameLength) {
	    Parent->MaxValueNameLength = NameLen;
	}
	if (Utf16NameLen > Parent->MaxUtf16ValueNameLength) {
	    Parent->MaxUtf16ValueNameLength = Utf16NameLen;
	}
	if (ValueDataLen > Parent->MaxValueDataLength) {
	    Parent->MaxValueDataLength = ValueDataLen;
	}
	if (Utf16ValueDataLen > Parent->MaxUtf16ValueDataLength) {
	    Parent->MaxUtf16ValueDataLength = Utf16ValueDataLen;
	}
    }
}

/*
 * Creation context for key object
 */
typedef struct _KEY_OBJECT_CREATE_CONTEXT {
    BOOLEAN Volatile;
} KEY_OBJECT_CREATE_CONTEXT, *PKEY_OBJECT_CREATE_CONTEXT;

/* key.c */
NTSTATUS CmpKeyObjectCreateProc(IN POBJECT Object,
				IN PVOID CreaCtx);
NTSTATUS CmpKeyObjectInsertProc(IN POBJECT Parent,
				IN POBJECT Subobject,
				IN PCSTR Subpath);
VOID CmpKeyObjectRemoveProc(IN POBJECT Parent,
			    IN POBJECT Subobject,
			    IN PCSTR Subpath);
NTSTATUS CmpKeyObjectParseProc(IN POBJECT Self,
			       IN PCSTR Path,
			       IN BOOLEAN CaseInsensitive,
			       OUT POBJECT *FoundObject,
			       OUT PCSTR *RemainingPath);
NTSTATUS CmpKeyObjectOpenProc(IN ASYNC_STATE State,
			      IN PTHREAD Thread,
			      IN POBJECT Object,
			      IN PCSTR SubPath,
			      IN ULONG Attributes,
			      IN POB_OPEN_CONTEXT OpenContext,
			      OUT POBJECT *pOpenedInstance,
			      OUT PCSTR *pRemainingPath);
VOID CmpKeyObjectDeleteProc(IN POBJECT Self);
VOID CmpDbgDumpKey(IN PCM_KEY_OBJECT Key);

/* value.c */
VOID CmpDbgDumpValue(IN PCM_REG_VALUE Value);
