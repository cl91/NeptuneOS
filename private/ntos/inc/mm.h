#pragma once

#include <nt.h>
#include <string.h>
#include <assert.h>
#include <services.h>
#include <avltree.h>

#ifdef MMDBG
#define MmDbg(...)	DbgTrace(__VA_ARGS__)
#define MmDbgPrint(...)	DbgPrint(__VA_ARGS__)
#else
#define MmDbg(...)
#define MmDbgPrint(...)
#endif

#define NTOS_MM_TAG			(EX_POOL_TAG('n','t','m','m'))

#define PAGE_ALIGNED_DATA		__aligned(PAGE_SIZE)
#define LARGE_PAGE_ALIGN(p)		((MWORD)(p) & ~(LARGE_PAGE_SIZE - 1))
#define LARGE_PAGE_ALIGN_UP(p)		(LARGE_PAGE_ALIGN((MWORD)(p)+LARGE_PAGE_SIZE-1))
#define IS_LARGE_PAGE_ALIGNED(p)	(((MWORD)(p)) == LARGE_PAGE_ALIGN(p))

#define NTOS_CNODE_CAP			(seL4_CapInitThreadCNode)
#define NTOS_VSPACE_CAP			(seL4_CapInitThreadVSpace)

#ifdef _WIN64
/* For 64-bit build we make the ExPool and other hard-coded address spaces bigger */
#define ADDRESS_SPACE_MULTIPLIER	(0x100)
#else
#define ADDRESS_SPACE_MULTIPLIER	(1)
#endif

/* All hard-coded addresses in the address space of the NTOS root task go here. */
#define FRAMEBUFFER_VADDR_START			(0x08000000ULL)
#define FRAMEBUFFER_MAX_SIZE			(0x06000000ULL)
/* System thread region is 16MB. Each system thread gets one page of IPC buffer and
 * four pages of stack. Every region is seperated by an uncommitted page to catch
 * stack overflow and underflow. In other words the memory organization is as follows
 *
 *    |---------------|-----------|------------|---------------|
 *    |    Stack      | Unmapped  | IPC Buffer |   Unmapped    |
 *    | 4 * PAGE_SIZE | PAGE_SIZE | PAGE_SIZE  | 2 * PAGE_SIZE |
 *    |---------------|-----------|------------|---------------|
 * (Lower address)                                      (Higher address)
 *
 * We can have a maximum of 16MB/32KB == 512 system threads.
 */
#define SYSTEM_THREAD_REGION_START		(FRAMEBUFFER_VADDR_START + FRAMEBUFFER_MAX_SIZE)
#define SYSTEM_THREAD_REGION_SIZE		(0x01000000ULL)
#define SYSTEM_THREAD_REGION_END		(SYSTEM_THREAD_REGION_START + SYSTEM_THREAD_REGION_SIZE)
#define SYSTEM_THREAD_STACK_COMMIT		(4 * PAGE_SIZE)
#define SYSTEM_THREAD_IPC_OFFSET		(SYSTEM_THREAD_STACK_COMMIT + PAGE_SIZE)
/* Hyperspace is 16MB */
#define HYPERSPACE_START			(SYSTEM_THREAD_REGION_END)
/* We have LARGE_PAGE_SIZE / PAGE_SIZE slots for 4K pages in the hyperspace */
#define HYPERSPACE_4K_PAGE_START		(HYPERSPACE_START)
/* We have one slot for large page in the hyperspace */
#define HYPERSPACE_LARGE_PAGE_START		(HYPERSPACE_4K_PAGE_START + LARGE_PAGE_SIZE)
#define HYPERSPACE_END				(HYPERSPACE_LARGE_PAGE_START + LARGE_PAGE_SIZE)
/* Region for the Executive pool. EX_POOL_MAX_SIZE must be a power of two.
 * Additionally, for amd64 EX_POOL_START must be within the first GB (since the initial
 * page directory and PDPT only cover the first GB). */
#define EX_POOL_START				(0x10000000ULL)
#define EX_POOL_MAX_SIZE			(0x10000000ULL * ADDRESS_SPACE_MULTIPLIER)
#define EX_POOL_END				(EX_POOL_START + EX_POOL_MAX_SIZE)
/* Region for the Large Object Executive Pool. Objects larger than one page size are
 * allocated from this pool. */
#define EX_LARGE_POOL_START			(EX_POOL_END)
#define EX_LARGE_POOL_SIZE			(0x10000000ULL * ADDRESS_SPACE_MULTIPLIER)
#define EX_LARGE_POOL_END			(EX_LARGE_POOL_START + EX_LARGE_POOL_SIZE)
/* Region where the driver processes' IO packet buffers are allocated, managed with bitmaps. */
#define EX_DRIVER_REGION_START			(EX_LARGE_POOL_END)
#define EX_DRIVER_REGION_SIZE			(0x10000000ULL * ADDRESS_SPACE_MULTIPLIER)
#define EX_DRIVER_REGION_END			(EX_DRIVER_REGION_START + EX_DRIVER_REGION_SIZE)
/* Region where the client thread's pages are mapped. This region is managed with bitmaps. */
#define EX_CLIENT_REGION_START			(EX_DRIVER_REGION_END)
#define EX_CLIENT_REGION_SIZE			(0x10000000ULL * ADDRESS_SPACE_MULTIPLIER)
#define EX_CLIENT_REGION_END			(EX_CLIENT_REGION_START + EX_CLIENT_REGION_SIZE)
/* Region of the dynamically managed Executive virtual address space */
#define EX_DYN_VSPACE_START			(EX_CLIENT_REGION_END)
#define EX_DYN_VSPACE_END			(seL4_UserTop)

#if HYPERSPACE_END > EX_POOL_START
#error "Hyperspace too large."
#endif

/* Since we use the object header's offset from the start of Executive pool as the
 * unique global object handle (badge), and on i386 the seL4 kernel ignores the highest
 * four bits of a badge, the Executive pool cannot be larger than 256MB. */
#if !defined(_WIN64) && (EX_POOL_MAX_SIZE > (1ULL << seL4_BadgeBits))
#error "Executive pool too large"
#endif

/* Since we use a device object's global handle right shifted by EX_POOL_BLOCK_SHIFT
 * as its (32-bit) WMI provider ID, the ExPool size cannot exceed 64GB on amd64. */
C_ASSERT(EX_POOL_MAX_SIZE <=
	 (1ULL << (32 + EX_POOL_BLOCK_SHIFT)));

/*
 * We use the following addressing scheme for the CSpace of a client thread
 *
 *   |------------------|------------|-------------|
 *   | Guard = ThreadId |      0     |Process CNode|
 *   |------------------|------------|-------------|
 *   | Guard = ThreadId |Thread CNode|      0      |
 *   |------------------|------------|-------------|
 *
 * Since on 32-bit architectures we use the full 18 guard bits for the thread ID,
 * the total bits used must be less than the 32. On 64-bit architectures the log2size
 * of ExPool should not exceed the number of guard bits plus EX_POOL_BLOCK_SHIFT
 */
#ifdef _WIN64
C_ASSERT(((seL4_GuardBits + EX_POOL_BLOCK_SHIFT) >= MWORD_BITS) ||
	 (EX_POOL_MAX_SIZE <= (1ULL << (seL4_GuardBits + EX_POOL_BLOCK_SHIFT))));
#else
C_ASSERT(PROCESS_SHARED_CNODE_LOG2SIZE + THREAD_PRIVATE_CNODE_LOG2SIZE + seL4_GuardBits <=
	 MWORD_BITS);
#endif

/* Allocation granularity for the system thread region, the client region and
 * the driver region. For the client region we reserve two pages but only
 * map one, so any buffer overflow or underflow is caught immediately. */
#define SYSTEM_THREAD_REGION_LOW_ZERO_BITS	(PAGE_LOG2SIZE + 3)
#define EX_CLIENT_REGION_LOW_ZERO_BITS		(PAGE_LOG2SIZE + 1)
#define EX_DRIVER_REGION_LOW_ZERO_BITS		(PAGE_LOG2SIZE + 4)

#if (1ULL << EX_CLIENT_REGION_LOW_ZERO_BITS) < IPC_BUFFER_RESERVE
#error "Client region allocation granularity too small."
#endif

#if (1ULL << EX_DRIVER_REGION_LOW_ZERO_BITS) < DRIVER_IO_PACKET_BUFFER_RESERVE
#error "Driver region allocation granularity too small."
#endif

/*
 * Capability derivation tree
 *
 * All seL4 kernel objects (aka capability) are assigned a capability
 * derivation tree node which is inserted into a capability derivation
 * tree, whose the root node is the root untyped capability from which
 * the child capability is ultimately derived. When capabilities are
 * minted, copied, or derived via Untyped_Retype, the new capabilities
 * are inserted into the capability derivation tree as the child of the
 * original capability. When a capability is moved or mutated, the
 * original tree node is updated with the new capability pointer. When
 * the capability is revoked, its children are deleted and freed (but
 * the node itself is not). When the capability is deleted, all its
 * children as well as the node itself are deleted and freed.
 *
 * The set of capability derivation trees derived from each root untyped
 * form the capability derivation forest. This forest is organized by
 * the physical address of the untyped caps in an AVL tree, and is stored
 * in the PHY_MEM_DESCRIPTOR struct as RootUntypedForest.
 *
 * Note: a CNode is always the leaf node of a capability derivation tree,
 * since a CNode cannot be minted or mutated. We do not directly copy a
 * CNode capability. When we are in the process of expanding a CNode, we
 * always create a new larger CNode and copy old capabilities into the new
 * one, and then delete the old CNode, releasing both ExPool memories and
 * freeing the untyped memory that the old CNode has claimed.
 */

typedef enum _CAP_TREE_NODE_TYPE {
    CAP_TREE_NODE_UNTYPED,
    CAP_TREE_NODE_CNODE,
    CAP_TREE_NODE_TCB,
    CAP_TREE_NODE_PAGING_STRUCTURE,
    CAP_TREE_NODE_ENDPOINT,
    CAP_TREE_NODE_NOTIFICATION,
    CAP_TREE_NODE_X86_IOPORT,
    CAP_TREE_NODE_IRQ_HANDLER
} CAP_TREE_NODE_TYPE;

/*
 * Node in the Capability Derivation Tree
 *
 * IMPORTANT: This must be the first member for all objects in the
 * CAP_TREE_NODE_TYPE.
 */
typedef struct _CAP_TREE_NODE {
    CAP_TREE_NODE_TYPE Type;
    MWORD Cap; /* Index into the CNode in which this cap is inserted. Note if this cap
		* is inserted into the outer CNode of a client thread (containing the
		* private caps of the thread objects) this index does not contain the
		* guard value of the outer CNode and the index bits of the inner CNode. */
    MWORD Badge; /* Badge (for IPC endpoint) or guard (if this cap is a CNode). */
    struct _CNODE *CNode;  /* CNode into which this cap is inserted. */
    struct _CAP_TREE_NODE *Parent; /* Cap from which this cap is derived. */
    LIST_ENTRY ChildrenList; /* List head of the sibling list of children. */
    LIST_ENTRY SiblingLink;  /* Chains all siblings together. */
} CAP_TREE_NODE, *PCAP_TREE_NODE;

static inline BOOLEAN MmCapTreeNodeHasChildren(IN PCAP_TREE_NODE Node)
{
    return !IsListEmpty(&Node->ChildrenList);
}

static inline SIZE_T MmCapTreeNodeChildrenCount(IN PCAP_TREE_NODE Node)
{
    return GetListLength(&Node->ChildrenList);
}

static inline SIZE_T MmCapTreeNodeSiblingCount(IN PCAP_TREE_NODE Node)
{
    return GetListLength(&Node->SiblingLink);
}

/*
 * A CNode represents a table of capability slots. It is
 * created by retyping a suitably-sized untyped capability.
 * The newly created CNode will be the child of the parent
 * untyped capability in the capability derivation tree.
 *
 * The root task starts with a (large) CNode as the single
 * layer of its CSpace. Each client thread gets a (small)
 * two-level CSpace where the outer CNode contains the
 * private caps of the thread object, with the zeroth cap
 * pointing to the inner CNode that contains the shared caps
 * of the thread object's process object. The guard bits of
 * the client thread's CSpace is set to its global handle
 * (right shifted by EX_POOL_BLOCK_SHIFT). Since the global
 * handle is the address of the object in the ExPool, the
 * log2size of the ExPool cannot exceed the number of guard
 * bits plus EX_POOL_BLOCK_SHIFT.
 */
typedef struct _CNODE {
    CAP_TREE_NODE TreeNode;	/* Must be first entry */
    MWORD *UsedMap;		/* Bitmap of used slots */
    ULONG Log2Size;		/* Called 'radix' in seL4 manual */
    ULONG RecentFree;		/* Most recently freed bit */
    ULONG TotalUsed;		/* Number of used slots */
} CNODE, *PCNODE;

#define TREE_NODE_TO_UNTYPED(Node) CONTAINING_RECORD(Node, UNTYPED, TreeNode)

/* The sum of PROCESS_SHARED_CNODE_LOG2SIZE and THREAD_PRIVATE_CNODE_LOG2SIZE
 * cannot be less than MWORD_BIT_LOG2SIZE, because seL4 does not support guard
 * bits larger than MWORD_BITS - MWORD_BITS_LOG2SIZE. Additionally, our BitMap
 * implementation requires that the number of bits is divisible by MWORD_BITS.
 * Therefore we require that the smallest CNode has MWORD_BITS slots. */
C_ASSERT(PROCESS_SHARED_CNODE_LOG2SIZE >= MWORD_BITS_LOG2SIZE);
C_ASSERT(THREAD_PRIVATE_CNODE_LOG2SIZE >= MWORD_BITS_LOG2SIZE);

static inline VOID MiCapTreeNodeSetParent(IN PCAP_TREE_NODE Self,
					  IN PCAP_TREE_NODE Parent)
{
    assert(Self != NULL);
    assert(Self != Parent);
    assert(Self->Parent == NULL);
    Self->Parent = Parent;
    if (Parent != NULL) {
	InsertTailList(&Parent->ChildrenList, &Self->SiblingLink);
    }
}

static inline VOID MmInitializeCapTreeNode(IN PCAP_TREE_NODE Self,
					   IN CAP_TREE_NODE_TYPE Type,
					   IN MWORD Cap,
					   IN PCNODE CSpace,
					   IN OPTIONAL PCAP_TREE_NODE Parent)
{
    assert(Self != NULL);
    assert(Cap < (1ULL << CSpace->Log2Size));
    Self->Type = Type;
    Self->Cap = Cap;
    Self->CNode = CSpace;
    InitializeListHead(&Self->ChildrenList);
    InitializeListHead(&Self->SiblingLink);
    MiCapTreeNodeSetParent(Self, Parent);
}

/*
 * Get the depth of the CPtr traversal needed for a capability in the given
 * CNode. This equals the radix of the CNode plus its number of guard bits.
 */
static inline ULONG MmCNodeGetDepth(IN PCNODE CNode)
{
    seL4_CNode_CapData_t GuardData = { .words[0] = CNode->TreeNode.Badge };
    ULONG GuardBits = seL4_CNode_CapData_get_guardSize(GuardData);
    return CNode->Log2Size + GuardBits;
}

/*
 * Get the depth of the CPtr traversal for the given cap tree node relative
 * to the CNode into which it is inserted. This depth value is supplied to
 * the seL4 CNode manipulation routines such as seL4_CNode_Copy.
 */
static inline ULONG MmCapTreeNodeGetDepth(IN PCAP_TREE_NODE Node)
{
    return MmCNodeGetDepth(Node->CNode);
}

/*
 * An untyped capability represents either free physical
 * memory or device memory mapped into the physical memory.
 * Both types of untyped capabilities are organized by
 * their starting physical memory address. An untyped node
 * therefore has a duality of membership, first in its capability
 * derivation tree, as well as in an AVL tree ordered by the
 * the physical memory address.
 */
typedef struct _UNTYPED {
    CAP_TREE_NODE TreeNode;	/* Must be first entry */
    AVL_NODE AvlNode;	/* Node ordered by physical address.
			 * For root untyped this is inserted into
			 * the root untyped forest. For non-root
			 * untyped the AvlNode.Key is used for book-
			 * keeping purpose only and the AVL node is
			 * not actually inserted into any AVL tree. */
    LIST_ENTRY FreeListEntry;	/* Applicable only for non-device untyped */
    LONG Log2Size;
    BOOLEAN IsDevice;
    BOOLEAN Requested; /* TRUE if the UNTYPED has been handed out by MmRequestUntyped.
			* An UNTYPED with children must have Requested == TRUE, but the
			* converse is not true. */
} UNTYPED, *PUNTYPED;

#define AVL_NODE_TO_UNTYPED(Node)					\
    ({									\
	PAVL_NODE __node = (Node);					\
	__node ? CONTAINING_RECORD(__node, UNTYPED, AvlNode) : NULL;	\
    })

/*
 * Virtual address descriptor
 *
 * A virtual address descriptor describes a contiguous region of pages within
 * the client process's virtual address space that have the same access rights,
 * attributes, and that belong to the same view of a section (or subsection).
 *
 * In terms of ownership of the memory pages within the VAD, there are two types
 * of VADs, owned memory region and mirrored memory region. Owned memory regions
 * allocate the pages by retyping untyped memories, while mirrored memory region
 * maps other owned memory regions via seL4_CNode_Copy, possibly with different
 * access rights.
 *
 * A VAD node does not in general track the commitment status of individual pages.
 * Callers of MMVAD routines must manage this themselves. An example here is the
 * cache manager that tracks the individual page commitment status via a multilevel
 * table structure (see CC_VIEW_TABLE, CC_VIEW, and relevant routines in Cc).
 *
 * A MirroredMemory is a type of VADs that map another OwnedMemory VAD (typically
 * within another VSpace) into a VSpace, possibly with a different WindowSize
 * and access rights. The commitment status of the MirroredMemory VAD is kept
 * in sync with the owned memory (within the address window of the mirrored VAD),
 * meaning that when the pages of the owned VAD are committed, the mirrored VAD
 * will have the corresponding pages mirrored as well, if these pages are within
 * the address window of the mirrored VAD.
 */
typedef union _MMVAD_FLAGS {
    struct {
	ULONG NoAccess : 1;   /* True if forbidden to access memory region */
	ULONG ReadOnly : 1;   /* If FALSE, page is mapped ReadWrite */
	ULONG ImageMap : 1; /* Node is a subsection of an image section */
	ULONG FileMap : 1;  /* Node is a view of a file section */
	ULONG CacheMap : 1; /* Node is managed by the cache manager */
	ULONG PhysicalMapping : 1; /* Node is a view of the physical memory */
	ULONG BitmapManaged : 1; /* Commitment status of node is managed by bitmaps */
	ULONG LargePages : 1; /* Use large pages when possible */
	ULONG OwnedMemory : 1; /* True if pages are owned by this VSpace */
	ULONG MirroredMemory : 1; /* True if this VAD is a mirror of another VAD */
	ULONG CommitOnDemand : 1; /* Memory will be committed as they are accessed */
    };
    ULONG Word;
} MMVAD_FLAGS;

/* Flags that can be passed into MmReserveVirtualMemoryEx */
#define MEM_RESERVE_NO_ACCESS		(0x1UL << 0)
#define MEM_RESERVE_READ_ONLY		(0x1UL << 1)
/* VADs representing a section view will be marked as IMAGE_MAP or FILE_MAP or
 * PHYSICAL_MAPPING. VADs for cache view will be marked as CACHE_MAP. VADs marked
 * with BITMAP_MANAGED will have their commitment status managed by bitmaps. VADs
 * for memory allocated by NtAllocateVirtualMemory and related internal Mm routines
 * will be marked as either "owned memory" or "mirrored memory". */
#define MEM_RESERVE_IMAGE_MAP		(0x1UL << 2)
#define MEM_RESERVE_FILE_MAP		(0x1UL << 3)
#define MEM_RESERVE_CACHE_MAP		(0x1UL << 4)
#define MEM_RESERVE_PHYSICAL_MAPPING	(0x1UL << 5)
#define MEM_RESERVE_BITMAP_MANAGED	(0x1UL << 6)
/* Memory pages are owned by this VSpace */
#define MEM_RESERVE_OWNED_MEMORY	(0x1UL << 7)
/* Memory pages are derived from pages in other VSpace via seL4_CNode_Copy */
#define MEM_RESERVE_MIRRORED_MEMORY	(0x1UL << 8)
/* If set, Mm will try to reserve an address window aligned by the large page size
 * and commit large pages when available. */
#define MEM_RESERVE_LARGE_PAGES		(0x1UL << 9)
/* Search from higher address to lower address */
#define MEM_RESERVE_TOP_DOWN		(0x1UL << 10)
/* Find unused address window only. Do not actually insert the VAD into the
 * process address space */
#define MEM_RESERVE_NO_INSERT		(0x1UL << 11)

typedef struct _MMVAD {
    AVL_NODE AvlNode; /* Starting virtual address of the node, page aligned */
    struct _VIRT_ADDR_SPACE *VSpace;
    MWORD WindowSize;		/* Rounded up to page boundary */
    MMVAD_FLAGS Flags;
    LIST_ENTRY SectionLink;	/* List entry for SECTION.VadList.
				 * If the VAD does not map a section
				 * view, this is unused. */
    union {
	struct {
	    struct _SECTION *Section;
	    MWORD SectionOffset; /* Rounded down to 4K page boundary */
	} DataSectionView;
	struct {
	    struct _SUBSECTION *SubSection;
	} ImageSectionView;
	struct {
	    MWORD PhysicalBase;	/* Base of the physical address window
				 * to map, page aligned */
	    PUNTYPED RootUntyped; /* Root untyped from which the physical memory
				   * of this VAD is allocated. This is only used
				   * in the case of map register memory. */
	    MEMORY_CACHING_TYPE CacheType; /* Cache type of the page mappings. */
	} PhysicalSectionView;	/* Physical section is neither owned
				 * nor mirrored memory */
	struct {
	    union {
		MWORD *Bitmap;	 /* Bitmap tracking the commitment status. */
		MWORD **Bitmaps; /* Array of bitmaps tracking the commitment status. */
	    };
	    ULONG LowZeroBits;	/* Allocation granularity. */
	} CommitmentStatus;
	struct {
	    struct _VIRT_ADDR_SPACE *Master; /* The VSpace that is been mapped
					      * into this VSpace */
	    MWORD StartAddr; /* Starting virtual address in the master vspace */
	    LIST_ENTRY ViewerLink;	/* List entry for master VSpace's ViewerList */
	} MirroredMemory;
    };
} MMVAD, *PMMVAD;

#define AVL_NODE_TO_VAD(Node)						\
    ({									\
	PAVL_NODE __node = (Node);					\
	__node ? CONTAINING_RECORD(__node, MMVAD, AvlNode) : NULL;	\
    })

/*
 * We support a maximum of four levels of paging structures. The lowest level
 * is PAGE, followed by PAGE TABLE, PAGE DIRECTORY, PDPT, and PML4. Some
 * non-X86 architectures may use different names for these paging structures,
 * but their functions are equivalent.
 */
#define PAGE_TABLE_OBJ_LOG2SIZE		(seL4_PageTableBits)
#define PAGE_TABLE_WINDOW_LOG2SIZE	(seL4_PageBits + seL4_PageTableIndexBits)

#if defined(_M_IX86) || defined(_M_AMD64)

#define PAGE_DIRECTORY_OBJ_LOG2SIZE	(seL4_PageDirBits)
#define PAGE_DIRECTORY_WINDOW_LOG2SIZE	(PAGE_TABLE_WINDOW_LOG2SIZE + seL4_PageDirIndexBits)

#ifdef _M_IX86
#define PDPT_OBJ_LOG2SIZE		(0)
#define PDPT_WINDOW_LOG2SIZE		(PAGE_DIRECTORY_WINDOW_LOG2SIZE)
#define PML4_OBJ_LOG2SIZE		(0)
#define PML4_WINDOW_LOG2SIZE		(PDPT_WINDOW_LOG2SIZE)
#define seL4_VSpaceObject		seL4_X86_PageDirectoryObject
#else
#define PDPT_OBJ_LOG2SIZE		(seL4_PDPTBits)
#define PDPT_WINDOW_LOG2SIZE		(PAGE_DIRECTORY_WINDOW_LOG2SIZE + seL4_PDPTIndexBits)
#define PML4_OBJ_LOG2SIZE		(seL4_PML4Bits)
#define PML4_WINDOW_LOG2SIZE		(PDPT_WINDOW_LOG2SIZE + seL4_PDPTIndexBits)
#define seL4_VSpaceObject		seL4_X64_PML4Object
#endif

typedef enum _PAGING_STRUCTURE_TYPE {
    PAGING_TYPE_PAGE = seL4_X86_4K,
    PAGING_TYPE_LARGE_PAGE = seL4_X86_LargePageObject,
    PAGING_TYPE_PAGE_TABLE = seL4_X86_PageTableObject,
    PAGING_TYPE_PAGE_DIRECTORY = seL4_X86_PageDirectoryObject,
#ifdef _M_IX86
    PAGING_TYPE_PDPT = 0,
    PAGING_TYPE_PML4 = 0,
#else
    PAGING_TYPE_PDPT = seL4_X86_PDPTObject,
    PAGING_TYPE_PML4 = seL4_X64_PML4Object,
#endif
    PAGING_TYPE_ROOT_PAGING_STRUCTURE = seL4_VSpaceObject,
} PAGING_STRUCTURE_TYPE;

typedef seL4_X86_VMAttributes PAGING_ATTRIBUTES;

#define MM_ATTRIBUTES_DEFAULT		(seL4_X86_Default_VMAttributes)

FORCEINLINE VOID MmApplyNoCacheAttribute(IN OUT PAGING_ATTRIBUTES *Attr)
{
    *Attr = seL4_X86_Uncacheable;
}

FORCEINLINE VOID MmApplyWriteCombineAttribute(IN OUT PAGING_ATTRIBUTES *Attr)
{
    *Attr = seL4_X86_WriteCombining;
}

typedef seL4_X86_Page_GetAddress_t seL4_Page_GetAddress_t;
#define seL4_Page_GetAddress seL4_X86_Page_GetAddress
#define seL4_Page_Map seL4_X86_Page_Map
#define seL4_Page_Unmap seL4_X86_Page_Unmap
#define seL4_PageTable_Map seL4_X86_PageTable_Map
#define seL4_PageTable_Unmap seL4_X86_PageTable_Unmap
#define seL4_PageDirectory_Map seL4_X86_PageDirectory_Map
#define seL4_PageDirectory_Unmap seL4_X86_PageDirectory_Unmap
#define seL4_PDPT_Map seL4_X86_PDPT_Map
#define seL4_PDPT_Unmap seL4_X86_PDPT_Unmap
#define seL4_ASIDPool_Assign seL4_X86_ASIDPool_Assign

#elif defined(_M_ARM64)

#define PAGE_DIRECTORY_OBJ_LOG2SIZE	(seL4_PageTableBits)
#define PAGE_DIRECTORY_WINDOW_LOG2SIZE	(PAGE_TABLE_WINDOW_LOG2SIZE + seL4_PageTableIndexBits)
#define PDPT_OBJ_LOG2SIZE		(seL4_PageTableBits)
#define PDPT_WINDOW_LOG2SIZE		(PAGE_DIRECTORY_WINDOW_LOG2SIZE + seL4_PageTableIndexBits)
#define PML4_OBJ_LOG2SIZE		(seL4_VSpaceBits)
#define PML4_WINDOW_LOG2SIZE		(PDPT_WINDOW_LOG2SIZE + seL4_VSpaceIndexBits)
#define seL4_VSpaceObject		seL4_ARM_VSpaceObject

typedef enum _PAGING_STRUCTURE_TYPE {
    PAGING_TYPE_PAGE = seL4_ARM_SmallPageObject,
    PAGING_TYPE_LARGE_PAGE = seL4_ARM_LargePageObject,
    PAGING_TYPE_PAGE_TABLE = seL4_ARM_PageTableObject,
    PAGING_TYPE_PAGE_DIRECTORY = seL4_ARM_PageTableObject,
    PAGING_TYPE_PDPT = seL4_ARM_PageTableObject,
    PAGING_TYPE_PML4 = seL4_VSpaceObject,
    PAGING_TYPE_ROOT_PAGING_STRUCTURE = seL4_VSpaceObject,
} PAGING_STRUCTURE_TYPE;

typedef seL4_ARM_VMAttributes PAGING_ATTRIBUTES;

#define MM_ATTRIBUTES_DEFAULT		(seL4_ARM_Default_VMAttributes)

FORCEINLINE VOID MmApplyNoCacheAttribute(IN OUT PAGING_ATTRIBUTES *Attr)
{
    *Attr &= ~seL4_ARM_PageCacheable;
}

FORCEINLINE VOID MmApplyWriteCombineAttribute(IN OUT PAGING_ATTRIBUTES *Attr)
{
    /* ARM64 doesn't seem to have a paging attribute for write combining memory. */
}

typedef seL4_ARM_Page_GetAddress_t seL4_Page_GetAddress_t;
#define seL4_Page_GetAddress seL4_ARM_Page_GetAddress
#define seL4_Page_Map seL4_ARM_Page_Map
#define seL4_Page_Unmap seL4_ARM_Page_Unmap
#define seL4_PageTable_Map seL4_ARM_PageTable_Map
#define seL4_PageTable_Unmap seL4_ARM_PageTable_Unmap
#define seL4_PageDirectory_Map seL4_ARM_PageTable_Map
#define seL4_PageDirectory_Unmap seL4_ARM_PageTable_Unmap
#define seL4_PDPT_Map seL4_ARM_PageTable_Map
#define seL4_PDPT_Unmap seL4_ARM_PageTable_Unmap
#define seL4_ASIDPool_Assign seL4_ARM_ASIDPool_Assign

#else
#error "Unsupported architecture"
#endif

typedef seL4_CapRights_t PAGING_RIGHTS;

#define MM_RIGHTS_RW	(seL4_ReadWrite)
#define MM_RIGHTS_RO	(seL4_CanRead)

/*
 * A paging structure represents a capability to either a page,
 * a large page, or a page table/page directory/PDPT/PML4/etc.
 * A paging structure has a unique virtual address space associated
 * with it, since to share a page in seL4 between multiple threads,
 * the capability to that page must first be cloned. Mapping the
 * same page cap twice is an error.
 *
 * Therefore, mapping a page on two different virtual address
 * spaces involves duplicating the PAGING_STRUCTURE first
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
typedef struct _PAGING_STRUCTURE {
    CAP_TREE_NODE TreeNode; /* Cap tree node of the page cap. Must be first member. */
    AVL_NODE AvlNode; /* AVL node of parent structure's SubStructureTree. Key is virt addr */
    struct _PAGING_STRUCTURE *SuperStructure; /* Parent structure, so for page it's
					       * page table, etc. */
    AVL_TREE SubStructureTree; /* Substructure tree, so for page table these are
				* the pages that were mapped into it, etc */
    MWORD VSpaceCap; /* Cap of the VSpace that this paging structure is mapped into */
    PAGING_STRUCTURE_TYPE Type;
    BOOLEAN Mapped;
    PAGING_RIGHTS Rights;
    PAGING_ATTRIBUTES Attributes;
} PAGING_STRUCTURE, *PPAGING_STRUCTURE;

#define AVL_NODE_TO_PAGING_STRUCTURE(Node)		\
    ({							\
	PAVL_NODE __node = (Node);			\
	__node ? CONTAINING_RECORD(__node,		\
				   PAGING_STRUCTURE,	\
				   AvlNode) : NULL;	\
    })

static inline BOOLEAN MmPagingRightsAreEqual(IN PAGING_RIGHTS Left,
					     IN PAGING_RIGHTS Right)
{
    return memcmp(&Left, &Right, sizeof(PAGING_RIGHTS)) == 0;
}

static inline BOOLEAN MmPageIsWritable(IN PPAGING_STRUCTURE Page)
{
    return MmPagingRightsAreEqual(Page->Rights, MM_RIGHTS_RW);
}

/*
 * Top level structure of the virtual address space of a process.
 *
 * This can represent both the root task's virtual address space
 * as well as client processes' virtual address spaces. For the
 * root task the Vad tree is not used.
 */
typedef struct _VIRT_ADDR_SPACE {
    MWORD VSpaceCap;		/* This is relative to the root task cspace */
    MWORD ASIDPool;
    AVL_TREE VadTree;
    PPAGING_STRUCTURE RootPagingStructure;
    LIST_ENTRY ViewerList;	/* List of all VADs that mirror pages in this VSpace */
} VIRT_ADDR_SPACE, *PVIRT_ADDR_SPACE;

/*
 * The top level structure for the memory management component.
 *
 * This represents the entire physical memory, consisting of both
 * all untyped caps (including device memory untyped caps). The
 * currently unused free memory are organized into three lists,
 * small, medium, and large, to speed up resource allocations.
 */
typedef struct _PHY_MEM_DESCRIPTOR {
    LIST_ENTRY LowMemUntypedList; /* Untyped with physical memory below MM_ISA_DMA_LIMIT. */
    LIST_ENTRY SmallUntypedList; /* *Free* untyped's that are smaller than one page */
    LIST_ENTRY MediumUntypedList; /* *Free* untyped's at least one page but smaller than one large page */
    LIST_ENTRY LargeUntypedList;  /* *Free* untyped's at least one large page */
    AVL_TREE RootUntypedForest; /* Root untyped forest organized by their starting phy addr.
				 * Note that RootUntypedForest represents both the cap derivation
				 * forest as well as the AVL tree of all untyped caps. */
} PHY_MEM_DESCRIPTOR, *PPHY_MEM_DESCRIPTOR;

typedef enum _MM_MEM_PRESSURE {
    MM_MEM_PRESSURE_SUFFICIENT_MEMORY,
    MM_MEM_PRESSURE_LOW_MEMORY,
    MM_MEM_PRESSURE_CRITICALLY_LOW_MEMORY
} MM_MEM_PRESSURE;

/* This defines what we consider as the "low memory region" of the physical address
 * space. These memories are reserved for 16-bit ISA devices and not allocated until
 * all high memory is exhausted. ISA DMA can only access the lowest 16MB of the
 * physical address space so we need to be extra frugal. */
#define MM_ISA_DMA_LIMIT	(16 * 1024 * 1024)

/*
 * Section object.
 *
 * A SECTION object describes the in-memory mapping of a FILE. The SECTION object
 * is managed by the object manager and exposed to the client processes (via an
 * instance handle). It is essentially a pointer into the actual IMAGE_SECTION_OBJECT
 * struct or DATA_SECTION_OBJECT struct. Since multiple SECTION objects can point
 * to the same FILE which can be mapped as image or data, the IO_FILE_OBJECT contains
 * pointers to both IMAGE_SECTION_OBJECT and DATA_SECTION_OBJECT.
 *
 * Note the nomenclatures here are somewhat confusing as the PE object format also has
 * a notion of "sections". A PE file can have multiple sections (.text, .data, etc)
 * which are loaded into memory according to its image headers (including the
 * section headers). During loading NTOS will create a SECTION object for the
 * PE file, which will simply be a pointer to an IMAGE_SECTION_OBJECT struct,
 * that contains multiple SUBSECTIONS each of which corresponds to a section
 * of the PE image file (plus one additional SUBSECTION for the PE image header).
 */
typedef union _MMSECTION_FLAGS {
    struct {
	ULONG Image : 1;
	ULONG Based : 1;
	ULONG File : 1;
	ULONG PhysicalMemory : 1;
	ULONG Reserve : 1;
	ULONG Commit : 1;
    };
    ULONG Word;
} MMSECTION_FLAGS;

typedef struct _SECTION {
    AVL_NODE BasedSectionNode; /* All SEC_BASED Sections are organized in an AVL tree */
    union {
	struct _IMAGE_SECTION_OBJECT *ImageSectionObject;
	struct _DATA_SECTION_OBJECT *DataSectionObject;
    };
    LIST_ENTRY Link;	/* For image sections and data sections, links all SECTION
			 * objects that share the same IMAGE/DATA_SECTION_OBJECT. */
    LIST_ENTRY VadList;	/* List of VADs that map a view of this section
			 * For image section, this includes all subsections. */
    MMSECTION_FLAGS Flags;
    ULONG Attributes;
    ULONG PageProtection; /* PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, etc. */
    MWORD Size;
} SECTION, *PSECTION;

typedef enum _IMAGE_SECTION_TYPE {
    PeImageSection,
    ElfImageSection
} IMAGE_SECTION_TYPE;

struct _IO_FILE_CONTROL_BLOCK;
struct _IO_FILE_OBJECT;
typedef struct _IMAGE_SECTION_OBJECT {
    struct _IO_FILE_CONTROL_BLOCK *Fcb;
    struct _IO_FILE_OBJECT *ImageCacheFile;
    LIST_ENTRY SubSectionList;
    LIST_ENTRY SectionList; /* List of all SECTION objects that share this image section */
    MWORD ImageBase;
    ULONG ImageCacheFileSize;
    SECTION_IMAGE_INFORMATION ImageInformation;
    IMAGE_SECTION_TYPE Type;
} IMAGE_SECTION_OBJECT, *PIMAGE_SECTION_OBJECT;

typedef struct _DATA_SECTION_OBJECT {
    struct _IO_FILE_CONTROL_BLOCK *Fcb;
    LIST_ENTRY SectionList;
} DATA_SECTION_OBJECT, *PDATA_SECTION_OBJECT;

/*
 * A subsection is a window of contiguous pages within a section. All
 * subsections that belong to a section are linked in its SubSectionList.
 */
typedef struct _SUBSECTION {
    PIMAGE_SECTION_OBJECT ImageSection;	/* Image section that this subsection belong to */
    LIST_ENTRY Link; /* Link for the owning image section's SubSectionList */
    UCHAR Name[IMAGE_SIZEOF_SHORT_NAME+1]; /* Name of the PE section (.text, .data, etc) */
    ULONG SubSectionSize; /* Size of the subsection in memory, page aligned. */
    ULONG FileOffset; /* Offset from the start of the file, file aligned */
    ULONG RawDataSize;   /* Size of the subsection, file aligned */
    ULONG SubSectionBase; /* Relative virtual address of the subsection, page aligned */
    ULONG ImageCacheFileOffset;	/* Offset of this subsection within the image cache file. */
    ULONG Characteristics; /* Section characteristics in the PE image section table. */
} SUBSECTION, *PSUBSECTION;

/*
 * Forward declarations
 */

/* init.c */
NTSTATUS MmInitSystemPhase0(IN seL4_BootInfo *bootinfo);
NTSTATUS MmInitSystemPhase1();
extern MWORD MmNumberOfPhysicalPages;
extern MWORD MmLowestPhysicalPage;
extern MWORD MmHighestPhysicalPage;

/* cap.c */
NTSTATUS MmAllocateCapRange(IN PCNODE CNode,
			    OUT MWORD *StartCap,
			    IN LONG NumberRequested);
VOID MmDeallocateCap(IN PCNODE CNode,
		     IN MWORD Cap);
NTSTATUS MmCreateCNode(IN ULONG Log2Size,
		       OUT PCNODE *pCNode);
VOID MmDeleteCNode(IN PCNODE CNode);
NTSTATUS MmCopyCap(IN PCNODE DestCSpace,
		   IN MWORD DestCap,
		   IN PCNODE SrcCSpace,
		   IN MWORD SrcCap,
		   IN seL4_CapRights_t NewRights);
NTSTATUS MmCapTreeCopyNode(IN PCAP_TREE_NODE NewNode,
			   IN PCAP_TREE_NODE OldNode,
			   IN seL4_CapRights_t NewRights);
NTSTATUS MmCapTreeDeriveBadgedNode(IN PCAP_TREE_NODE NewNode,
				   IN PCAP_TREE_NODE OldNode,
				   IN seL4_CapRights_t NewRights,
				   IN MWORD Badge);
VOID MmCapTreeDeleteNode(IN PCAP_TREE_NODE Node);

static inline NTSTATUS MmAllocateCap(IN PCNODE CNode,
				     OUT MWORD *Cap)
{
    return MmAllocateCapRange(CNode, Cap, 1);
}

/* untyped.c */
NTSTATUS MmRequestUntypedEx(IN LONG Log2Size,
			    IN MWORD HighestPhyAddr,
			    OUT PUNTYPED *pUntyped);
VOID MmReleaseUntyped(IN PUNTYPED Untyped);
NTSTATUS MmRetypeIntoObject(IN PUNTYPED Untyped,
			    IN MWORD ObjType,
			    IN MWORD ObjBits,
			    IN PCAP_TREE_NODE TreeNode);

static inline NTSTATUS MmRequestUntyped(IN LONG Log2Size,
					OUT PUNTYPED *pUntyped)
{
    return MmRequestUntypedEx(Log2Size, 0, pUntyped);
}

/* page.c */
MM_MEM_PRESSURE MmQueryMemoryPressure();
NTSTATUS MmCommitOwnedMemoryEx(IN PVIRT_ADDR_SPACE VSpace,
			       IN MWORD StartAddr,
			       IN MWORD WindowSize,
			       IN PAGING_RIGHTS Rights,
			       IN PAGING_ATTRIBUTES Attributes,
			       IN BOOLEAN UseLargePages,
			       IN OPTIONAL PVOID DataBuffer,
			       IN OPTIONAL MWORD BufferSize);
NTSTATUS MmMapMirroredMemory(IN PVIRT_ADDR_SPACE OwnerVSpace,
			     IN MWORD OwnerStartAddr,
			     IN PVIRT_ADDR_SPACE ViewerVSpace,
			     IN MWORD ViewerStartAddr,
			     IN MWORD WindowSize,
			     IN PAGING_RIGHTS NewRights,
			     IN PAGING_ATTRIBUTES NewAttributes);

static inline NTSTATUS MmCommitOwnedMemory(IN MWORD StartAddr,
					   IN MWORD WindowSize,
					   IN PAGING_RIGHTS Rights,
					   IN BOOLEAN UseLargePages)
{
    extern VIRT_ADDR_SPACE MiNtosVaddrSpace;
    return MmCommitOwnedMemoryEx(&MiNtosVaddrSpace, StartAddr, WindowSize, Rights,
				 MM_ATTRIBUTES_DEFAULT, UseLargePages, NULL, 0);
}

/* section.c */
NTSTATUS MmSectionInitialization();
struct _ASYNC_STATE;
struct _THREAD;
NTSTATUS MmCreateSection(IN struct _IO_FILE_OBJECT *FileObject,
			 IN ULONG PageProtection,
			 IN ULONG SectionAttribute,
			 OUT PSECTION *SectionObject);
NTSTATUS MmCreateSectionEx(IN struct _ASYNC_STATE State,
			   IN struct _THREAD *Thread,
			   IN struct _IO_FILE_OBJECT *FileObject,
			   IN ULONG PageProtection,
			   IN ULONG SectionAttributes,
			   OUT PSECTION *SectionObject);
NTSTATUS MmMapViewOfSection(IN PVIRT_ADDR_SPACE VSpace,
			    IN PSECTION Section,
			    IN OUT MWORD *BaseAddress,
			    IN OUT ULONG64 *SectionOffset,
			    IN OUT MWORD *ViewSize,
			    IN ULONG HighZeroBits,
			    IN SECTION_INHERIT InheritDisposition,
			    IN ULONG ReserveFlags,
			    IN ULONG AccessProtection);
NTSTATUS MmMapPhysicalMemory(IN ULONG64 PhysicalBase,
			     IN MWORD VirtualBase,
			     IN MWORD WindowSize,
			     IN ULONG PageProtection);
VOID MmUnmapPhysicalMemory(IN MWORD VirtAddr);

/* vaddr.c */
NTSTATUS MmCreateVSpace(IN PVIRT_ADDR_SPACE Self);
VOID MmDestroyVSpace(IN PVIRT_ADDR_SPACE Self);
NTSTATUS MmAssignASID(IN PVIRT_ADDR_SPACE VaddrSpace);
NTSTATUS MmReserveVirtualMemoryEx(IN PVIRT_ADDR_SPACE VSpace,
				  IN MWORD StartAddr,
				  IN OPTIONAL MWORD EndAddr,
				  IN MWORD WindowSize,
				  IN ULONG LowZeroBits,
				  IN ULONG HighZeroBits,
				  IN MWORD Flags,
				  OUT OPTIONAL PMMVAD *pVad);
NTSTATUS MmCommitVirtualMemoryEx(IN PVIRT_ADDR_SPACE VSpace,
				 IN MWORD StartAddr,
				 IN MWORD WindowSize);
VOID MmUncommitVirtualMemoryEx(IN PVIRT_ADDR_SPACE VSpace,
			       IN MWORD StartAddr,
			       IN MWORD WindowSize);
MWORD MmFindAndMarkUncommittedSubregion(IN PMMVAD Vad);
NTSTATUS MmAllocatePhysicallyContiguousMemory(IN PVIRT_ADDR_SPACE VSpace,
					      IN MWORD Length,
					      IN MWORD HighestPhyAddr,
					      IN MEMORY_CACHING_TYPE CacheType,
					      OUT MWORD *VirtAddr,
					      OUT MWORD *PhyAddr);
NTSTATUS MmFreePhysicallyContiguousMemory(IN PVIRT_ADDR_SPACE VSpace,
					  IN MWORD VirtAddr,
					  IN MWORD Length,
					  IN MEMORY_CACHING_TYPE CacheType);
NTSTATUS MmTryCommitWindowRW(IN PVIRT_ADDR_SPACE VSpace,
			     IN MWORD StartAddr,
			     IN MWORD WindowSize);
PPAGING_STRUCTURE MmQueryPageEx(IN PVIRT_ADDR_SPACE VSpace,
				IN MWORD VirtAddr,
				IN BOOLEAN LargePage);
BOOLEAN MmGeneratePageFrameDatabase(IN OPTIONAL PULONG_PTR PfnDb,
				    IN PVIRT_ADDR_SPACE VSpace,
				    IN MWORD Buffer,
				    IN MWORD BufferLength,
				    OUT OPTIONAL ULONG *pPfnCount);
VOID MmRegisterMirroredVad(IN PMMVAD Viewer,
			   IN PMMVAD MasterVad);
VOID MmRegisterMirroredMemory(IN PMMVAD Viewer,
			      IN PVIRT_ADDR_SPACE Master,
			      IN MWORD StartAddr);
VOID MmDeleteVad(IN PMMVAD Vad);
NTSTATUS MmMapUserBufferEx(IN PVIRT_ADDR_SPACE VSpace,
			   IN MWORD BufferStart,
			   IN MWORD BufferLength,
			   IN PVIRT_ADDR_SPACE TargetVSpace,
			   IN MWORD TargetVaddrStart,
			   IN MWORD TargetVaddrEnd,
			   OUT MWORD *TargetStartAddr,
			   IN BOOLEAN ReadOnly);
VOID MmUnmapRegion(IN PVIRT_ADDR_SPACE MappedVSpace,
		   IN MWORD MappedRegionStart);
NTSTATUS MmMapHyperspacePage(IN PVIRT_ADDR_SPACE VSpace,
			     IN MWORD Address,
			     IN BOOLEAN Write,
			     OUT PVOID *MappedAddress,
			     OUT ULONG *MappedLength);
VOID MmUnmapHyperspacePage(IN PVOID MappedAddress);
struct _THREAD;
BOOLEAN MmHandleThreadVmFault(IN struct _THREAD *Thread,
			      IN MWORD Addr);

static inline NTSTATUS MmReserveVirtualMemory(IN MWORD StartAddr,
					      IN OPTIONAL MWORD EndAddr,
					      IN MWORD WindowSize,
					      IN ULONG LowZeroBits,
					      IN MWORD Flags,
					      OUT OPTIONAL PMMVAD *pVad)
{
    extern VIRT_ADDR_SPACE MiNtosVaddrSpace;
    return MmReserveVirtualMemoryEx(&MiNtosVaddrSpace, StartAddr, EndAddr,
				    WindowSize, LowZeroBits, 0, Flags, pVad);
}

static inline NTSTATUS MmCommitVirtualMemory(IN MWORD StartAddr,
					     IN MWORD WindowSize)
{
    extern VIRT_ADDR_SPACE MiNtosVaddrSpace;
    return MmCommitVirtualMemoryEx(&MiNtosVaddrSpace, StartAddr, WindowSize);
}

static inline VOID MmUncommitVirtualMemory(IN MWORD StartAddr,
					   IN MWORD WindowSize)
{
    extern VIRT_ADDR_SPACE MiNtosVaddrSpace;
    MmUncommitVirtualMemoryEx(&MiNtosVaddrSpace, StartAddr, WindowSize);
}


static inline PPAGING_STRUCTURE MmQueryPage(IN MWORD VirtAddr)
{
    extern VIRT_ADDR_SPACE MiNtosVaddrSpace;
    return MmQueryPageEx(&MiNtosVaddrSpace, VirtAddr, FALSE);
}

/*
 * Maps the user buffer in the given virt addr space into the server
 * virt addr space, returning the starting virtual address of the
 * buffer in the server virt addr space. The user buffer must be
 * writable by the user. Otherwise STATUS_INVALID_PAGE_PROTECTION
 * is returned.
 */
static inline NTSTATUS MmMapUserBuffer(IN PVIRT_ADDR_SPACE VSpace,
				       IN MWORD BufferStart,
				       IN MWORD BufferLength,
				       OUT PVOID *TargetStartAddr)
{
    extern VIRT_ADDR_SPACE MiNtosVaddrSpace;
    return MmMapUserBufferEx(VSpace, BufferStart, BufferLength,
			     &MiNtosVaddrSpace, EX_DYN_VSPACE_START,
			     EX_DYN_VSPACE_END, (MWORD *)TargetStartAddr,
			     FALSE);
}

/*
 * Maps the user buffer in the given virt addr space into the server
 * virt addr space, returning the starting virtual address of the
 * buffer in the server virt addr space. The pages will be mapped
 * read-only. User buffer is not required to be writable by the user.
 */
static inline NTSTATUS MmMapUserBufferRO(IN PVIRT_ADDR_SPACE VSpace,
					 IN MWORD BufferStart,
					 IN MWORD BufferLength,
					 OUT PVOID *TargetStartAddr)
{
    extern VIRT_ADDR_SPACE MiNtosVaddrSpace;
    return MmMapUserBufferEx(VSpace, BufferStart, BufferLength,
			     &MiNtosVaddrSpace, EX_DYN_VSPACE_START,
			     EX_DYN_VSPACE_END, (MWORD *)TargetStartAddr,
			     TRUE);
}

/*
 * Unmap the server address window specified by the start address.
 * This will look up the VAD corresponding to the window start and
 * delete the VAD.
 */
static inline VOID MmUnmapServerRegion(IN MWORD WindowStart)
{
    extern VIRT_ADDR_SPACE MiNtosVaddrSpace;
    return MmUnmapRegion(&MiNtosVaddrSpace, WindowStart);
}

/*
 * Unmaps the the user buffer mapped by MmMapUserBuffer.
 */
static inline VOID MmUnmapUserBuffer(IN PVOID UserBuffer)
{
    return MmUnmapServerRegion((MWORD)UserBuffer);
}

/*
 * Debug helper functions
 */
VOID MmDbgDumpCapTreeNode(IN PCAP_TREE_NODE Node);
VOID MmDbgDumpCNode(IN PCNODE CNode);
VOID MmDbgDumpCapTree(IN PCAP_TREE_NODE Root,
		      IN LONG Indentation);
VOID MmDbgDumpUntypedForest();
VOID MmDbgDumpPagingStructure(IN PPAGING_STRUCTURE Paging);
VOID MmDbgDumpPagingStructureRecursively(IN PPAGING_STRUCTURE Paging);
VOID MmDbgDumpSection(IN PSECTION Section);
VOID MmDbgDumpVad(PMMVAD Vad);
VOID MmDbgDumpVSpace(PVIRT_ADDR_SPACE VSpace);
