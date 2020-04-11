#pragma once

#include <nt.h>
#include "ntosdef.h"

/* Information needed to initialize the Executive Pool */
typedef struct _MM_INIT_INFO_CLASS {
    MWORD InitVSpaceCap;
    MWORD InitUntypedCap;
    LONG InitUntypedLog2Size;
    MWORD RootCNodeCap;
    LONG RootCNodeLog2Size;
    MWORD RootCNodeFreeCapStart;
    LONG RootCNodeFreeCapNumber;
} MM_INIT_INFO_CLASS, *PMM_INIT_INFO_CLASS;

/* Describes the entire CapSpace */
typedef struct _MM_CAPSPACE {
    MWORD RootCap;
    struct _MM_CNODE *RootCNode;
} MM_CAPSPACE, *PMM_CAPSPACE;

typedef enum _MM_CAP_TREE_NODE_TYPE {
				     MM_CAP_TREE_NODE_CNODE,
				     MM_CAP_TREE_NODE_UNTYPED,
				     MM_CAP_TREE_NODE_PAGING_STRUCTURE,
} MM_CAP_TREE_NODE_TYPE;

/* Describes a node in the Capability Derivation Tree */
typedef struct _MM_CAP_TREE_NODE {
    PMM_CAPSPACE CapSpace;
    struct _MM_CAP_TREE_NODE *Parent;
    struct _MM_CAP_TREE_NODE *LeftChild;
    struct _MM_CAP_TREE_NODE *RightChild;
    MM_CAP_TREE_NODE_TYPE Type;
} MM_CAP_TREE_NODE, *PMM_CAP_TREE_NODE;

/* Describes a single CNode */
typedef struct _MM_CNODE {
    MM_CAP_TREE_NODE TreeNode;	/* Must be first entry */
    MWORD Log2Size;
    struct _MM_CNODE *FirstChild;
    LIST_ENTRY SiblingList;
    enum { MM_CNODE_TAIL_DEALLOC_ONLY, MM_CNODE_ALLOW_DEALLOC } Policy;
    union {
	PUCHAR UsedMap;
	struct {
	    MWORD StartCap;  /* Full CPtr to the starting cap */
	    LONG Number;     /* Indicate range [Start,Start+Number) */
	} FreeRange;
    };
} MM_CNODE, *PMM_CNODE;

typedef struct _MM_UNTYPED {
    MM_CAP_TREE_NODE TreeNode;	/* Must be first entry */
    seL4_Word Cap;
    LONG Log2Size;
    BOOLEAN Split;
} MM_UNTYPED, *PMM_UNTYPED;

typedef enum _MM_PAGING_STRUCTURE_TYPE { MM_PAGE_TYPE_PAGE,
					 MM_PAGE_TYPE_LARGE_PAGE,
					 MM_PAGE_TYPE_PAGE_TABLE,
} MM_PAGING_STRUCTURE_TYPE;

typedef struct _MM_PAGING_STRUCTURE {
    MM_CAP_TREE_NODE TreeNode;	/* Must be first entry */
    MWORD Cap;
    MWORD VSpaceCap;
    MM_PAGING_STRUCTURE_TYPE Type;
    BOOLEAN Mapped;
    MWORD VirtualAddr;
    seL4_CapRights_t Rights;
    seL4_X86_VMAttributes Attributes;
} MM_PAGING_STRUCTURE, *PMM_PAGING_STRUCTURE;

NTSTATUS MmRegisterClass(IN PMM_INIT_INFO_CLASS InitInfo);
NTSTATUS MmRegisterUntyped(IN MWORD Untyped, LONG Log2Size);
NTSTATUS MmRequestUntyped(IN LONG Log2Size, OUT MM_UNTYPED *Untyped);

#define MM_RIGHTS_RW	(seL4_ReadWrite)

typedef struct _MM_AVL_NODE {
    MWORD Parent;
    struct _MM_AVL_NODE *LeftChild;
    struct _MM_AVL_NODE *RightChild;
    MWORD StartingPageNumber;
    LIST_ENTRY ListEntry;			    /* all node ordered linearly according to StartingPageNumber */
} MM_AVL_NODE, *PMM_AVL_NODE;

typedef struct _MM_AVL_TREE {
    PMM_AVL_NODE BalancedRoot;
    LIST_ENTRY NodeList;	/* ordered linearly according to StartingPageNumber */
} MM_AVL_TREE, *PMM_AVL_TREE;

typedef struct _MM_PAGE_TABLE {
    PMM_PAGING_STRUCTURE PagingStructure; /* must be first entry. See MM_VAD */
    LIST_ENTRY LargePageListEntry;		     /* linked with page table/large pages from low address to high address */
    MM_AVL_TREE MappedPages;		     /* balanced tree for all mapped pages */
} MM_PAGE_TABLE, *PMM_PAGE_TABLE;

typedef struct _MM_LARGE_PAGE {
    PMM_PAGING_STRUCTURE PagingStructure; /* must be first entry. See MM_VAD */
    LIST_ENTRY LargePageListEntry;		     /* linked with page table/large pages from low address to high address */
} MM_LARGE_PAGE, *PMM_LARGE_PAGE;

typedef struct _MM_PAGE {
    MM_AVL_NODE AvlNode;	/* must be first entry */
    PMM_PAGING_STRUCTURE PagingStructure;
} MM_PAGE, *PMM_PAGE;

/* Virtual address descriptor */
typedef struct _MM_VAD {
    MM_AVL_NODE AvlNode;	/* must be first entry */
    MWORD NumberOfPages;
    PMM_PAGING_STRUCTURE *FirstLargePage; /* polymorphic pointers to either MM_LARGE_PAGE */
    PMM_PAGING_STRUCTURE *LastLargePage; /* or MM_PAGE_TABLE */
} MM_VAD, *PMM_VAD;

typedef struct _MM_VIRTUAL_ADDRESS_SPACE {
    MM_CAPSPACE CapSpace;
    MM_AVL_TREE VadTree;
} MM_VIRTUAL_ADDRESS_SPACE, *PMM_VIRTUAL_ADDRESS_SPACE;
