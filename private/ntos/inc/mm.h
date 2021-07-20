#pragma once

#include <nt.h>
#include "ntosdef.h"

#define NTOS_MM_TAG			(EX_POOL_TAG('n','t','m','m'))

#define PAGE_LOG2SIZE			(seL4_PageBits)
#define PAGE_TABLE_OBJ_LOG2SIZE		(seL4_PageTableBits)
#define PAGE_TABLE_WINDOW_LOG2SIZE	(seL4_PageBits + seL4_PageDirIndexBits)
#define LARGE_PAGE_LOG2SIZE		(seL4_LargePageBits)
#define PAGE_DIRECTORY_OBJ_LOG2SIZE	(seL4_PageDirBits)
#define PAGE_DIRECTORY_WINDOW_LOG2SIZE	(PAGE_TABLE_WINDOW_LOG2SIZE + seL4_PageDirIndexBits)
#define PAGE_SIZE			(1 << PAGE_LOG2SIZE)
#define LARGE_PAGE_SIZE			(1 << LARGE_PAGE_LOG2SIZE)

#define PAGE_ALIGN(p)			((MWORD)(p) & ~(PAGE_SIZE - 1))
#define IS_PAGE_ALIGNED(p)		(((MWORD)(p)) == PAGE_ALIGN(p))
#define PAGE_ALIGNED_DATA		__aligned(PAGE_SIZE)
#define LARGE_PAGE_ALIGN(p)		((MWORD)(p) & ~(LARGE_PAGE_SIZE - 1))
#define IS_LARGE_PAGE_ALIGNED(p)	(((MWORD)(p)) == LARGE_PAGE_ALIGN(p))

#define ROOT_CNODE_CAP			(seL4_CapInitThreadCNode)
#define ROOT_VSPACE_CAP			(seL4_CapInitThreadVSpace)

#ifdef _M_IX86
#define MWORD_LOG2SIZE			(2)
#define seL4_VSpaceObject		seL4_X86_PageDirectoryObject
#define PDPT_OBJ_LOG2SIZE		(0)
#define PDPT_WINDOW_LOG2SIZE		(PAGE_DIRECTORY_WINDOW_LOG2SIZE)
#define PML4_OBJ_LOG2SIZE		(0)
#define PML4_WINDOW_LOG2SIZE		(PDPT_WINDOW_LOG2SIZE)
#elif defined(_M_AMD64)
#define MWORD_LOG2SIZE			(3)
#define seL4_VSpaceObject		seL4_X64_PML4Object
#define PDPT_OBJ_LOG2SIZE		(seL4_PDPTBits)
#define PDPT_WINDOW_LOG2SIZE		(PAGE_DIRECTORY_WINDOW_LOG2SIZE + seL4_PDPTIndexBits)
#define PML4_OBJ_LOG2SIZE		(seL4_PML4Bits)
#define PML4_WINDOW_LOG2SIZE		(PDPT_WINDOW_LOG2SIZE + seL4_PDPTIndexBits)
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

#define MM_AVL_NODE_TO_UNTYPED(Node)					\
    ((Node) != NULL ? CONTAINING_RECORD(Node, MM_UNTYPED, AvlNode) : NULL)

/*
 * Virtual address descriptor
 *
 * This data structure is used for keeping track of the client
 * process's request to reserve virtual address space. The memory
 * manager's internal routines do not rely on this information
 * to map or unmap a paging structure.
 */
typedef struct _MM_VAD {
    MM_AVL_NODE AvlNode;	/* must be first entry */
    MWORD WindowSize;
} MM_VAD, *PMM_VAD;

#define MM_AVL_NODE_TO_VAD(Node)					\
    ((Node) != NULL ? CONTAINING_RECORD(Node, MM_VAD, AvlNode) : NULL)

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
 * structure will be the child of the old paging structure
 * in the capability derivation tree.
 *
 * The virtual address space data structure of a process keeps
 * track of the full page mapping information of the virtual
 * address space. The page mapping is done in multiple layers,
 * which for x86 has three, page directory, page table, and pages.
 *
 * All pages belonging to the same page table are inserted via the
 * AvlNode member into an AVL tree denoted by the page table's
 * SubStructureTree member. Likewise, all page tables belonging
 * to a page directory are linked into an AVL tree via its AvlNode
 * member. The SuperStructure member points to the paging structure
 * one level above the current paging structure. The top level paging
 * structure is recorded in the process's virtual address space descriptor.
 */
typedef enum _MM_PAGING_STRUCTURE_TYPE {
    MM_PAGING_TYPE_PAGE = seL4_X86_4K,
    MM_PAGING_TYPE_LARGE_PAGE = seL4_X86_LargePageObject,
    MM_PAGING_TYPE_PAGE_TABLE = seL4_X86_PageTableObject,
    MM_PAGING_TYPE_PAGE_DIRECTORY = seL4_X86_PageDirectoryObject,
    MM_PAGING_TYPE_ROOT_PAGING_STRUCTURE = seL4_VSpaceObject,
#ifdef _M_IX86
    MM_PAGING_TYPE_PDPT = 0,
    MM_PAGING_TYPE_PML4 = 0,
#elif defined(_M_AMD64)
    MM_PAGING_TYPE_PDPT = seL4_X64_PDPTObject,
    MM_PAGING_TYPE_PML4 = seL4_X64_PML4Object,
#else
#error "Unsupported architecture"
#endif
} MM_PAGING_STRUCTURE_TYPE;

#define MM_PAGING_RIGHTS		seL4_CapRights_t
#define MM_PAGING_ATTRIBUTES		seL4_X86_VMAttributes

typedef struct _MM_PAGING_STRUCTURE {
    MM_CAP_TREE_NODE TreeNode;
    MM_AVL_NODE AvlNode;
    struct _MM_PAGING_STRUCTURE *SuperStructure;
    MM_AVL_TREE SubStructureTree;
    MWORD VSpaceCap;
    MM_PAGING_STRUCTURE_TYPE Type;
    BOOLEAN Mapped;
    MM_PAGING_RIGHTS Rights;
    MM_PAGING_ATTRIBUTES Attributes;
} MM_PAGING_STRUCTURE, *PMM_PAGING_STRUCTURE;

#define MM_AVL_NODE_TO_PAGING_STRUCTURE(Node)					\
    ((Node) != NULL ? CONTAINING_RECORD(Node, MM_PAGING_STRUCTURE, AvlNode) : NULL)

#define MM_RIGHTS_RW	(seL4_ReadWrite)

typedef ULONG WIN32_PROTECTION_MASK;
typedef PULONG PWIN32_PROTECTION_MASK;

/*
 * Top level structure of the virtual address space of a process.
 *
 * This can represent both the root task's virtual address space
 * as well as client processes' virtual address spaces. For the
 * root task the Vad tree contains exactly one node, spanning the
 * entire virtual address space.
 */
typedef struct _MM_VADDR_SPACE {
    MWORD VSpaceCap;		/* This is relative to the root task cspace */
    MM_AVL_TREE VadTree;
    PMM_VAD CachedVad;		/* Speed up look up */
    MM_PAGING_STRUCTURE RootPagingStructure;
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


/*
 * Forward declarations
 */

/* init.c */
NTSTATUS MmInitSystem(IN seL4_BootInfo *bootinfo);

/* avltree.c */
VOID MmAvlDumpTree(PMM_AVL_TREE tree);
VOID MmAvlDumpTreeLinear(PMM_AVL_TREE tree);

/* cap.c */
VOID MmDbgDumpCapTreeNode(IN PMM_CAP_TREE_NODE Node);
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
VOID MmDbgDumpUntypedInfo();

/* page.c */
MM_MEM_PRESSURE MmQueryMemoryPressure();
NTSTATUS MmCommitAddrWindowEx(IN PMM_VADDR_SPACE VaddrSpace,
			      IN MWORD VirtAddr,
			      IN MWORD Size,
			      IN MM_PAGING_RIGHTS Rights,
			      IN BOOLEAN UseLargePage,
			      OUT OPTIONAL MWORD *pSatisfiedSize,
			      OUT OPTIONAL PMM_PAGING_STRUCTURE *pPage,
			      IN OPTIONAL LONG MaxNumPagingStruct,
			      OUT OPTIONAL LONG *pNumPagingStruct);
NTSTATUS MmCommitIoPageEx(IN PMM_VADDR_SPACE VaddrSpace,
			  IN PMM_PHY_MEM PhyMem,
			  IN MWORD PhyAddr,
			  IN MWORD VirtAddr,
			  IN MM_PAGING_RIGHTS Rights,
			  OUT OPTIONAL PMM_PAGING_STRUCTURE *pPage);
VOID MmDbgDumpPagingStructure(IN PMM_PAGING_STRUCTURE Paging);

static inline NTSTATUS MmCommitIoPage(IN MWORD PhyAddr,
				      IN MWORD VirtAddr)
{
    extern MM_VADDR_SPACE MiNtosVaddrSpace;
    extern MM_PHY_MEM MiPhyMemDescriptor;
    return MmCommitIoPageEx(&MiNtosVaddrSpace, &MiPhyMemDescriptor,
			    PhyAddr, VirtAddr, MM_RIGHTS_RW, NULL);
}

/*
 * Commit an address window in the NTOS Root Task, using large pages if available.
 */
static inline NTSTATUS MmCommitAddrWindow(IN MWORD VirtAddr,
					  IN MWORD Size,
					  OUT OPTIONAL MWORD *pSatisfiedSize)
{
    extern MM_VADDR_SPACE MiNtosVaddrSpace;
    return MmCommitAddrWindowEx(&MiNtosVaddrSpace, VirtAddr, Size, MM_RIGHTS_RW,
				TRUE, pSatisfiedSize, NULL, 0, NULL);
}

/* vaddr.c */
VOID MmInitializeVaddrSpace(IN PMM_VADDR_SPACE VaddrSpace,
			    IN MWORD VSpaceCap);
NTSTATUS MmReserveVirtualMemoryEx(IN PMM_VADDR_SPACE Vspace,
				  IN MWORD VirtAddr,
				  IN MWORD WindowSize);

static inline NTSTATUS MmReserveVirtualMemory(IN MWORD VirtAddr,
					      IN MWORD WindowSize)
{
    extern MM_VADDR_SPACE MiNtosVaddrSpace;
    return MmReserveVirtualMemoryEx(&MiNtosVaddrSpace, VirtAddr, WindowSize);
}
