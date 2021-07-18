#pragma once

#include <nt.h>
#include "ntosdef.h"

#define NTOS_MM_TAG    		(EX_POOL_TAG('n','t','m','m'))

#define PAGE_LOG2SIZE		(seL4_PageBits)
#define PAGE_TABLE_LOG2SIZE	(seL4_PageBits)
#define LARGE_PAGE_LOG2SIZE	(seL4_LargePageBits)
#define PAGE_SIZE		(1 << PAGE_LOG2SIZE)
#define LARGE_PAGE_SIZE		(1 << LARGE_PAGE_LOG2SIZE)

#define PAGE_ALIGN(p)		((MWORD)(p) & ~(PAGE_SIZE - 1))
#define IS_PAGE_ALIGNED(p)	(((MWORD)(p)) == PAGE_ALIGN(p))
#define PAGE_ALIGNED_DATA	__aligned(PAGE_SIZE)

#define ROOT_CNODE_CAP		(seL4_CapInitThreadCNode)
#define ROOT_VSPACE_CAP		(seL4_CapInitThreadVSpace)

#ifdef _M_IX86
#define MWORD_LOG2SIZE	(2)
#elif defined(_M_AMD64)
#define MWORD_LOG2SIZE	(3)
#else
#error "Unsupported architecture"
#endif

/*
 * Capability derivation tree
 *
 * All seL4 kernel objects with a capability are assigned
 * a capability tree node and are inserted into a
 * capability derivation tree, starting from the root
 * untyped from which they are derived. When capabilities
 * are minted, copied, or derived via Untyped_Retype, the
 * new capabilities are inserted into the capability
 * derivation tree as the child of the original capability.
 * When a capability is moved or mutated, the original
 * tree node is updated to have the new capability pointer.
 * When the capability is revoked, its children are deleted
 * and freed (but the tree node itself is not). When the
 * capability is deleted, all its children as well as the
 * node itself are deleted and freed.
 *
 * The set of capability derivation trees derived from
 * each root untyped form the capability derivation forest.
 * This forest is organized by the physical address of
 * the untyped caps in an AVL tree, and is stored in the
 * MM_PHY_MEM struct as RootUntypedForest.
 *
 * Note: a CNode is always the leaf node of a capability
 * derivation tree, since a CNode cannot be minted or mutated.
 * We do not directly copy a CNode capability. When we are
 * in the process of expanding a CNode, we always create a new
 * larger CNode and copy old capabilities into the new one,
 * and then delete the old CNode, releasing both ExPool memories
 * and freeing the untyped memory that the old CNode has claimed.
*/

typedef enum _MM_CAP_TREE_NODE_TYPE {
    MM_CAP_TREE_NODE_CNODE,
    MM_CAP_TREE_NODE_UNTYPED,
    MM_CAP_TREE_NODE_PAGING_STRUCTURE,
} MM_CAP_TREE_NODE_TYPE;

/* Describes a node in the Capability Derivation Tree */
typedef struct _MM_CAP_TREE_NODE {
    MM_CAP_TREE_NODE_TYPE Type;
    MWORD Cap;			/* Relative to the root task CSpace */
    struct _MM_CAP_TREE_NODE *Parent;
    LIST_ENTRY ChildrenList;	/* List head of the sibling list of children */
    LIST_ENTRY SiblingLink;	/* Chains all siblings together */
} MM_CAP_TREE_NODE, *PMM_CAP_TREE_NODE;

/*
 * A CNode represents a table of capability slots. It is
 * created by retyping a suitably-sized untyped capability.
 * The newly created CNode will be the child of the parent
 * untyped capability in the capability derivation tree.
 *
 * The root task starts with a (large) CNode as the single
 * layer of its CSpace. Each client process gets a (small)
 * CNode as its single layer of CSpace. The guard bits are
 * always zero and are suitably sized such that no remaining
 * bits are to be resolved in a capability lookup.
 */
typedef struct _MM_CNODE {
    MM_CAP_TREE_NODE TreeNode;	/* Must be first entry */
    MWORD *UsedMap;		/* Bitmap of used slots */
    ULONG Log2Size;		/* Called 'radix' in seL4 manual */
    ULONG RecentFree;		/* Most recently freed bit */
    ULONG TotalUsed;		/* Number of used slots */
} MM_CNODE, *PMM_CNODE;

/*
 * A tree node in the AVL tree
 */
typedef struct _MM_AVL_NODE {
    MWORD Parent;
    struct _MM_AVL_NODE *LeftChild;
    struct _MM_AVL_NODE *RightChild;
    MWORD Key; /* key is usually address, page number, or large page number */
    LIST_ENTRY ListEntry; /* all node ordered linearly according to key */
} MM_AVL_NODE, *PMM_AVL_NODE;

/*
 * AVL tree ordered by the key of the tree node
 */
typedef struct _MM_AVL_TREE {
    PMM_AVL_NODE BalancedRoot;
    LIST_ENTRY NodeList;       /* ordered linearly according to key */
} MM_AVL_TREE, *PMM_AVL_TREE;

/*
 * An untyped capability represents either free physical
 * memory or device memory mapped into the physical memory.
 * Both types of untyped capabilities are organized by
 * their starting physical memory address. An untyped node
 * therefore has a duality of membership, first in its capability
 * derivation tree, as well as in an AVL tree ordered by the
 * the physical memory address.
 */
typedef struct _MM_UNTYPED {
    MM_CAP_TREE_NODE TreeNode;	/* Must be first entry */
    MM_AVL_NODE AvlNode;	/* Node ordered by physical address */
    LIST_ENTRY FreeListEntry;	/* Applicable only for non-device untyped */
    LONG Log2Size;
    BOOLEAN IsDevice;
} MM_UNTYPED, *PMM_UNTYPED;

/* Virtual address descriptor */
typedef struct _MM_VAD {
    MM_AVL_NODE AvlNode;	/* must be first entry */
    MWORD NumPages;
    PMM_AVL_NODE FirstPageTable; /* point to first and last page table/large page in the vaddr range */
    PMM_AVL_NODE LastPageTable;	 /* polymorphic pointers to either MM_LARGE_PAGE or MM_PAGE_TABLE */
} MM_VAD, *PMM_VAD;

/*
 * Top level structure of the virtual address space of a process
 */
typedef struct _MM_VADDR_SPACE {
    MWORD VSpaceCap;		/* This is relative to the root task cspace */
    MM_AVL_TREE VadTree;
    MM_AVL_TREE PageTableTree;	/* Node is either a page table or a large page */
    PMM_VAD CachedVad;		/* Speed up look up */
} MM_VADDR_SPACE, *PMM_VADDR_SPACE;

/*
 * The top level structure for the memory management component.
 *
 * This represents the entire physical memory, consisting of both
 * all untyped caps (including device memory untyped caps). The
 * currently unused free memory are organized into three lists,
 * small, medium, and large, to speed up resource allocations.
 */
typedef struct _MM_PHY_MEM {
    LIST_ENTRY SmallUntypedList; /* *Free* untyped's that are smaller than one page */
    LIST_ENTRY MediumUntypedList; /* *Free* untyped's at least one page but smaller than one large page */
    LIST_ENTRY LargeUntypedList;  /* *Free* untyped's at least one large page */
    MM_AVL_TREE RootUntypedForest; /* Root untyped forest organized by their starting phy addr.
				    * Note that RootUntypedForest represents both the cap derivation
				    * forest as well as the AVL tree of all untyped caps. */
    PMM_UNTYPED CachedRootUntyped; /* Speed up look up */
} MM_PHY_MEM, *PMM_PHY_MEM;

typedef enum _MM_MEM_PRESSURE {
    MM_MEM_PRESSURE_SUFFICIENT_MEMORY,
    MM_MEM_PRESSURE_LOW_MEMORY,
    MM_MEM_PRESSURE_CRITICALLY_LOW_MEMORY
} MM_MEM_PRESSURE;

/* Forward declarations */
typedef struct _MM_PAGE MM_PAGE, *PMM_PAGE;

/* init.c */
NTSTATUS MmInitSystem(IN seL4_BootInfo *bootinfo);

/* cap.c */
NTSTATUS MmAllocateCapRangeEx(IN PMM_CNODE CNode,
			      OUT MWORD *StartCap,
			      IN LONG NumberRequested);
NTSTATUS MmDeallocateCapEx(IN PMM_CNODE CNode,
			   IN MWORD Cap);
NTSTATUS MmCreateCNode(IN ULONG Log2Size,
		       OUT PMM_CNODE *pCNode);
NTSTATUS MmDeleteCNode(PMM_CNODE CNode);

static inline NTSTATUS MmAllocateCap(OUT MWORD *Cap)
{
    extern MM_CNODE MiNtosCNode;
    return MmAllocateCapRangeEx(&MiNtosCNode, Cap, 1);
}

static inline NTSTATUS MmAllocateCapRange(OUT MWORD *StartCap,
					  IN LONG NumberRequested)
{
    extern MM_CNODE MiNtosCNode;
    return MmAllocateCapRangeEx(&MiNtosCNode, StartCap, NumberRequested);
}

static inline NTSTATUS MmDeallocateCap(IN MWORD Cap)
{
    extern MM_CNODE MiNtosCNode;
    return MmDeallocateCapEx(&MiNtosCNode, Cap);
}

/* untyped.c */
NTSTATUS MmRequestUntyped(IN LONG Log2Size,
			  OUT PMM_UNTYPED *pUntyped);
NTSTATUS MmReleaseUntyped(IN PMM_UNTYPED Untyped);
NTSTATUS MmRetypeIntoObject(IN PMM_UNTYPED Untyped,
			    IN MWORD ObjType,
			    IN MWORD ObjBits,
			    OUT MWORD *ObjCap);

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

static inline NTSTATUS MmCommitPageEx(IN PMM_VADDR_SPACE VaddrSpace,
				      IN MWORD StartPageNum,
				      OUT OPTIONAL PMM_PAGE *Page)
{
    MWORD SatisfiedPages;
    return MmCommitPagesEx(VaddrSpace, StartPageNum, 1, &SatisfiedPages, Page);
}

static inline NTSTATUS MmCommitPage(IN MWORD StartPageNum,
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
