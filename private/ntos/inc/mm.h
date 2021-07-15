#pragma once

#include <nt.h>
#include "ntosdef.h"

#define NTOS_MM_TAG    		(EX_POOL_TAG('n','t','m','m'))

#define MM_PAGE_BITS		(seL4_PageBits)
#define MM_PAGE_TABLE_BITS	(seL4_PageBits)
#define MM_LARGE_PAGE_BITS	(seL4_LargePageBits)
#define MM_LARGE_PN_SHIFT	(MM_LARGE_PAGE_BITS - MM_PAGE_BITS)
#define MM_PAGE_SIZE		(1 << MM_PAGE_BITS)
#define MM_LARGE_PAGE_SIZE	(1 << MM_LARGE_PAGE_BITS)

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
    LONG Log2Size;
    enum { MM_CNODE_TAIL_DEALLOC_ONLY, MM_CNODE_ALLOW_DEALLOC } Policy;
    union {
	PUCHAR UsedMap;
	struct {
	    MWORD StartCap;  /* Full CPtr to the starting cap */
	    LONG Number;     /* Indicate range [Start,Start+Number) */
	} FreeRange;
    };
} MM_CNODE, *PMM_CNODE;

typedef enum _MM_PAGING_STRUCTURE_TYPE {
    MM_PAGE_TYPE_PAGE,
    MM_PAGE_TYPE_LARGE_PAGE,
    MM_PAGE_TYPE_PAGE_TABLE,
} MM_PAGING_STRUCTURE_TYPE;

/*
 * A paging structure represents a capability to either a page,
 * a large page, or a page table. A paging structure has a unique
 * virtual address space associated with it, since to share a
 * page in seL4 between multiple threads, the capability to that
 * page must first be cloned. Mapping the same page cap twice is
 * an error.
 *
 * Therefore, mapping a page on two different virtual address
 * spaces involves duplicating the MM_PAGING_STRUCTURE first
 * and then map the new paging structure. The new paging
 * structure will be the left child of the old paging structure
 * in the capability derivation tree.
 */
typedef struct _MM_PAGING_STRUCTURE {
    MM_CAP_TREE_NODE TreeNode;	/* Must be first entry */
    MWORD VSpaceCap;
    MM_PAGING_STRUCTURE_TYPE Type;
    BOOLEAN Mapped;
    MWORD VirtPageNum;
    seL4_CapRights_t Rights;
    seL4_X86_VMAttributes Attributes;
} MM_PAGING_STRUCTURE, *PMM_PAGING_STRUCTURE;

#define MM_RIGHTS_RW	(seL4_ReadWrite)

typedef ULONG WIN32_PROTECTION_MASK;
typedef PULONG PWIN32_PROTECTION_MASK;

typedef struct _MM_AVL_NODE {
    MWORD Parent;
    struct _MM_AVL_NODE *LeftChild;
    struct _MM_AVL_NODE *RightChild;
    MWORD Key;			/* key is usually address, page number, or large page number */
    LIST_ENTRY ListEntry; /* all node ordered linearly according to key */
} MM_AVL_NODE, *PMM_AVL_NODE;

typedef struct _MM_AVL_TREE {
    PMM_AVL_NODE BalancedRoot;
    LIST_ENTRY NodeList;	/* ordered linearly according to key */
} MM_AVL_TREE, *PMM_AVL_TREE;

typedef struct _MM_LARGE_PAGE {
    MM_AVL_NODE AvlNode;		  /* must be first entry. See MM_VAD */
    MM_PAGING_STRUCTURE PagingStructure; /* must be second entry */
} MM_LARGE_PAGE, *PMM_LARGE_PAGE;

typedef struct _MM_PAGE_TABLE {
    MM_AVL_NODE AvlNode;		  /* must be first entry. See MM_VAD */
    MM_PAGING_STRUCTURE PagingStructure; /* must be second entry */
    MM_AVL_TREE MappedPages;  /* balanced tree for all mapped pages */
} MM_PAGE_TABLE, *PMM_PAGE_TABLE;

typedef struct _MM_PAGE {
    MM_AVL_NODE AvlNode;	/* must be first entry */
    MM_PAGING_STRUCTURE PagingStructure;
} MM_PAGE, *PMM_PAGE;

/* Virtual address descriptor */
typedef struct _MM_VAD {
    MM_AVL_NODE AvlNode;	/* must be first entry */
    MWORD NumPages;
    PMM_AVL_NODE FirstPageTable; /* point to first and last page table/large page in the vaddr range */
    PMM_AVL_NODE LastPageTable;	 /* polymorphic pointers to either MM_LARGE_PAGE or MM_PAGE_TABLE */
} MM_VAD, *PMM_VAD;

typedef struct _MM_VADDR_SPACE {
    MWORD VSpaceCap;
    MM_AVL_TREE VadTree;
    MM_AVL_TREE PageTableTree;	/* Node is either a page table or a large page */
    PMM_VAD CachedVad;		/* speed up look up */
} MM_VADDR_SPACE, *PMM_VADDR_SPACE;

typedef struct _MM_UNTYPED {
    MM_CAP_TREE_NODE TreeNode;	/* Must be first entry */
    MM_AVL_NODE AvlNode;	/* Node ordered by physical address */
    LIST_ENTRY FreeListEntry;	/* Applicable only for non-device untyped */
    LONG Log2Size;
    BOOLEAN IsDevice;
} MM_UNTYPED, *PMM_UNTYPED;

typedef struct _MM_PHY_MEM {
    LIST_ENTRY SmallUntypedList; /* *Free* untyped's that are smaller than one page */
    LIST_ENTRY MediumUntypedList; /* *Free* untyped's at least one page but smaller than one large page */
    LIST_ENTRY LargeUntypedList;  /* *Free* untyped's at least one large page */
    MM_AVL_TREE RootUntypedTree; /* Root untyped organized by their starting phy addr */
    PMM_UNTYPED CachedRootUntyped; /* speed up look up */
} MM_PHY_MEM, *PMM_PHY_MEM;

typedef enum _MM_MEM_PRESSURE {
    MM_MEM_PRESSURE_SUFFICIENT_MEMORY,
    MM_MEM_PRESSURE_LOW_MEMORY,
    MM_MEM_PRESSURE_CRITICALLY_LOW_MEMORY
} MM_MEM_PRESSURE;

/* init.c */
NTSTATUS MmInitSystem(IN seL4_BootInfo *bootinfo);

/* cap.c */
NTSTATUS MmAllocateCap(OUT MWORD *Cap);
NTSTATUS MmAllocateCaps(OUT MWORD *StartCap,
			IN LONG NumberRequested);
NTSTATUS MmDeallocateCap(IN MWORD Cap);
MWORD MmRootCspaceCap();

/* untyped.c */
NTSTATUS MmRequestUntyped(IN LONG Log2Size,
			  OUT PMM_UNTYPED *pUntyped);
NTSTATUS MmReleaseUntyped(IN PMM_UNTYPED Untyped);

/* page.c */
MM_MEM_PRESSURE MmQueryMemoryPressure();
NTSTATUS MmCommitPages(IN MWORD FirstPageNum,
		       IN MWORD NumPages,
		       OUT MWORD *SatisfiedPages,
		       OUT OPTIONAL PMM_PAGE *Pages);
NTSTATUS MmCommitPagesEx(IN PMM_VADDR_SPACE VaddrSpace,
			 IN MWORD StartPageNum,
			 IN MWORD NumPages,
			 OUT MWORD *SatisfiedPages,
			 OUT OPTIONAL PMM_PAGE *Pages);
NTSTATUS MmCommitIoPageEx(IN PMM_VADDR_SPACE VaddrSpace,
			  IN PMM_PHY_MEM PhyMem,
			  IN MWORD PhyPageNum,
			  IN MWORD VirtPageNum);
NTSTATUS MmCommitIoPage(IN MWORD PhyPageNum,
			IN MWORD VirtPageNum);

static inline NTSTATUS
MmCommitPageEx(IN PMM_VADDR_SPACE VaddrSpace,
	       IN MWORD StartPageNum,
	       OUT OPTIONAL PMM_PAGE *Page)
{
    MWORD SatisfiedPages;
    return MmCommitPagesEx(VaddrSpace, StartPageNum, 1, &SatisfiedPages, Page);
}

static inline NTSTATUS
MmCommitPage(IN MWORD StartPageNum,
	     OUT OPTIONAL PMM_PAGE *Page)
{
    MWORD SatisfiedPages;
    return MmCommitPages(StartPageNum, 1, &SatisfiedPages, Page);
}

/* vaddr.c */
VOID MmInitializeVaddrSpace(IN PMM_VADDR_SPACE VaddrSpace,
			    IN MWORD VspaceCap);
NTSTATUS MmReserveVirtualMemory(IN MWORD StartPageNum,
				IN MWORD NumPages);
NTSTATUS MmReserveVirtualMemoryEx(IN PMM_VADDR_SPACE Vspace,
				  IN MWORD StartPageNum,
				  IN MWORD NumPages);
