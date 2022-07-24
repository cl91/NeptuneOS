#pragma once

/* Comment this to enable debug tracing */
#define NDEBUG

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
    union {
	ULONG Dword;
	ULONGLONG Qword;
	struct {
	    PVOID Data;		/* Must be first in this struct */
	    ULONG DataSize;
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
	if (!strncmp(Name, NodeName, NameLength)) {
	    NodeFound = Node;
	}
    }
    return NodeFound;
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
			       OUT POBJECT *FoundObject,
			       OUT PCSTR *RemainingPath);
NTSTATUS CmpKeyObjectOpenProc(IN ASYNC_STATE State,
			      IN PTHREAD Thread,
			      IN POBJECT Object,
			      IN PCSTR SubPath,
			      IN POB_OPEN_CONTEXT OpenContext,
			      OUT POBJECT *pOpenedInstance,
			      OUT PCSTR *pRemainingPath);
VOID CmpKeyObjectDeleteProc(IN POBJECT Self);
VOID CmpDbgDumpKey(IN PCM_KEY_OBJECT Key);

/* value.c */
VOID CmpDbgDumpValue(IN PCM_REG_VALUE Value);
