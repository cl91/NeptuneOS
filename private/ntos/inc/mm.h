#pragma once

#include <nt.h>
#include "ntosdef.h"

#define NTOS_MM_TAG    			(EX_POOL_TAG('n','t','m','m'))

#define MM_PAGE_BITS		(seL4_PageBits)
#define MM_PAGE_TABLE_BITS	(seL4_PageBits)
#define MM_LARGE_PAGE_BITS	(seL4_LargePageBits)
#define MM_LARGE_PN_SHIFT	(MM_LARGE_PAGE_BITS - MM_PAGE_BITS)
#define MM_PAGE_SIZE		(1 << MM_PAGE_BITS)
#define MM_LARGE_PAGE_SIZE	(1 << MM_LARGE_PAGE_BITS)

/* Information needed to initialize the Memory Management routines,
 * including the Executive Pool */
typedef struct _MM_INIT_INFO_CLASS {
    MWORD InitVSpaceCap;
    MWORD InitUntypedCap;
    ULONG InitUntypedLog2Size;
    MWORD RootCNodeCap;
    ULONG RootCNodeLog2Size;
    MWORD RootCNodeFreeCapStart;
    ULONG RootCNodeFreeCapNumber;
    struct _EPROCESS *EProcess;
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
    MWORD Cap;
    struct _MM_CAP_TREE_NODE *Parent;
    struct _MM_CAP_TREE_NODE *LeftChild;
    struct _MM_CAP_TREE_NODE *RightChild;
    MM_CAP_TREE_NODE_TYPE Type;
} MM_CAP_TREE_NODE, *PMM_CAP_TREE_NODE;

/* Describes a single CNode */
typedef struct _MM_CNODE {
    MM_CAP_TREE_NODE TreeNode;	/* Must be first entry */
    struct _MM_CNODE *FirstChild;
    LIST_ENTRY SiblingList;
    ULONG Log2Size;
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
    LIST_ENTRY FreeListEntry;
    LIST_ENTRY RootListEntry;
    LONG Log2Size;
} MM_UNTYPED, *PMM_UNTYPED;

typedef enum _MM_PAGING_STRUCTURE_TYPE { MM_PAGE_TYPE_PAGE,
					 MM_PAGE_TYPE_LARGE_PAGE,
					 MM_PAGE_TYPE_PAGE_TABLE,
} MM_PAGING_STRUCTURE_TYPE;

typedef struct _MM_PAGING_STRUCTURE {
    MM_CAP_TREE_NODE TreeNode;	/* Must be first entry */
    MWORD VSpaceCap;
    MM_PAGING_STRUCTURE_TYPE Type;
    BOOLEAN Mapped;
    MWORD VirtualAddr;
    seL4_CapRights_t Rights;
    seL4_X86_VMAttributes Attributes;
} MM_PAGING_STRUCTURE, *PMM_PAGING_STRUCTURE;

#define MM_RIGHTS_RW	(seL4_ReadWrite)

typedef struct _MM_AVL_NODE {
    MWORD Parent;
    struct _MM_AVL_NODE *LeftChild;
    struct _MM_AVL_NODE *RightChild;
    MWORD StartPageNum;
    LIST_ENTRY ListEntry;			    /* all node ordered linearly according to StartPageNum */
} MM_AVL_NODE, *PMM_AVL_NODE;

typedef struct _MM_AVL_TREE {
    PMM_AVL_NODE BalancedRoot;
    LIST_ENTRY NodeList;	/* ordered linearly according to StartPageNum */
} MM_AVL_TREE, *PMM_AVL_TREE;

typedef struct _MM_LARGE_PAGE {
    MM_AVL_NODE AvlNode;		  /* must be first entry. See MM_VAD */
    PMM_PAGING_STRUCTURE PagingStructure; /* must be second entry */
} MM_LARGE_PAGE, *PMM_LARGE_PAGE;

typedef struct _MM_PAGE_TABLE {
    MM_AVL_NODE AvlNode;		  /* must be first entry. See MM_VAD */
    PMM_PAGING_STRUCTURE PagingStructure; /* must be second entry */
    MM_AVL_TREE MappedPages;  /* balanced tree for all mapped pages */
} MM_PAGE_TABLE, *PMM_PAGE_TABLE;

typedef struct _MM_PAGE {
    MM_AVL_NODE AvlNode;	/* must be first entry */
    PMM_PAGING_STRUCTURE PagingStructure;
} MM_PAGE, *PMM_PAGE;

/* Virtual address descriptor */
typedef struct _MM_VAD {
    MM_AVL_NODE AvlNode;	/* must be first entry */
    MWORD NumPages;
    PMM_AVL_NODE FirstPageTable; /* point to first and last page table/large page in the vaddr range */
    PMM_AVL_NODE LastPageTable;	 /* polymorphic pointers to either MM_LARGE_PAGE or MM_PAGE_TABLE */
} MM_VAD, *PMM_VAD;

typedef struct _MM_VADDR_SPACE {
    MM_CAPSPACE CapSpace;
    MWORD VSpaceCap;
    MM_AVL_TREE VadTree;
    MM_AVL_TREE PageTableTree;	/* Node is either a page table or a large page */
    LIST_ENTRY SmallUntypedList; /* *Free* untyped's that are smaller than one page */
    LIST_ENTRY MediumUntypedList; /* *Free* untyped's at least one page but smaller than one large page */
    LIST_ENTRY LargeUntypedList;  /* *Free* untyped's at least one large page */
    LIST_ENTRY RootUntypedList; /* Root untyped's (including used and unused) */
} MM_VADDR_SPACE, *PMM_VADDR_SPACE;

typedef enum _MM_MEM_PRESSURE {
			       MM_MEM_PRESSURE_LOW,
			       MM_MEM_PRESSURE_MEDIUM,
			       MM_MEM_PRESSURE_HIGH
} MM_MEM_PRESSURE;

/* init.c */
NTSTATUS MmRegisterClass(IN PMM_INIT_INFO_CLASS InitInfo);
NTSTATUS MmRegisterRootUntyped(IN PMM_VADDR_SPACE VaddrSpace,
			       IN MWORD Cap,
			       IN MWORD Log2Size);

/* untyped.c */
NTSTATUS MmRequestUntyped(IN LONG Log2Size,
			  OUT MM_UNTYPED *Untyped);

/* page.c */
MM_MEM_PRESSURE MmQueryMemoryPressure();
NTSTATUS MmCommitPages(IN PMM_VADDR_SPACE VaddrSpace,
		       IN MWORD StartPageNum,
		       IN MWORD NumPages,
		       OUT MWORD *SatisfiedPages);
