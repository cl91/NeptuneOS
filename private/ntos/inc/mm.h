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
#define PAGE_SIZE			(1ULL << PAGE_LOG2SIZE)
#define LARGE_PAGE_SIZE			(1ULL << LARGE_PAGE_LOG2SIZE)

#define PAGE_ALIGN(p)			((MWORD)(p) & ~(PAGE_SIZE - 1))
#define IS_PAGE_ALIGNED(p)		(((MWORD)(p)) == PAGE_ALIGN(p))
#define PAGE_ALIGNED_DATA		__aligned(PAGE_SIZE)
#define LARGE_PAGE_ALIGN(p)		((MWORD)(p) & ~(LARGE_PAGE_SIZE - 1))
#define IS_LARGE_PAGE_ALIGNED(p)	(((MWORD)(p)) == LARGE_PAGE_ALIGN(p))
#define PAGE_ALIGN_UP(p)		(PAGE_ALIGN((MWORD)(p) + PAGE_SIZE - 1))

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
 * PHY_MEM_DESCRIPTOR struct as RootUntypedForest.
 *
 * Note: a CNode is always the leaf node of a capability
 * derivation tree, since a CNode cannot be minted or mutated.
 * We do not directly copy a CNode capability. When we are
 * in the process of expanding a CNode, we always create a new
 * larger CNode and copy old capabilities into the new one,
 * and then delete the old CNode, releasing both ExPool memories
 * and freeing the untyped memory that the old CNode has claimed.
*/

typedef enum _CAP_TREE_NODE_TYPE {
    CAP_TREE_NODE_CNODE,
    CAP_TREE_NODE_UNTYPED,
    CAP_TREE_NODE_PAGING_STRUCTURE,
} CAP_TREE_NODE_TYPE;

/* Describes a node in the Capability Derivation Tree */
typedef struct _CAP_TREE_NODE {
    CAP_TREE_NODE_TYPE Type;
    MWORD Cap;			/* Relative to the root task CSpace */
    struct _CAP_TREE_NODE *Parent;
    LIST_ENTRY ChildrenList;	/* List head of the sibling list of children */
    LIST_ENTRY SiblingLink;	/* Chains all siblings together */
} CAP_TREE_NODE, *PCAP_TREE_NODE;

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
typedef struct _CNODE {
    CAP_TREE_NODE TreeNode;	/* Must be first entry */
    MWORD *UsedMap;		/* Bitmap of used slots */
    ULONG Log2Size;		/* Called 'radix' in seL4 manual */
    ULONG RecentFree;		/* Most recently freed bit */
    ULONG TotalUsed;		/* Number of used slots */
} CNODE, *PCNODE;

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
typedef struct _UNTYPED {
    CAP_TREE_NODE TreeNode;	/* Must be first entry */
    MM_AVL_NODE AvlNode;	/* Node ordered by physical address */
    LIST_ENTRY FreeListEntry;	/* Applicable only for non-device untyped */
    LONG Log2Size;
    BOOLEAN IsDevice;
} UNTYPED, *PUNTYPED;

#define MM_AVL_NODE_TO_UNTYPED(Node)					\
    ((Node) != NULL ? CONTAINING_RECORD(Node, UNTYPED, AvlNode) : NULL)

/*
 * Virtual address descriptor
 *
 * This data structure is used for keeping track of the client
 * process's request to reserve virtual address space. The memory
 * manager's internal routines do not rely on this information
 * to map or unmap a paging structure.
 */
typedef union _MMVAD_FLAGS {
    struct {
	MWORD PrivateMemory : 1; /* Section pointer is null */
	MWORD ImageMap : 1;
	MWORD LargePages : 1;
	MWORD MemCommit: 1;
	MWORD PhysicalMapping : 1;
    };
    MWORD Word;
} MMVAD_FLAGS;

typedef struct _MMVAD {
    MM_AVL_NODE AvlNode;	/* must be first entry */
    MMVAD_FLAGS Flags;
    MWORD WindowSize;		/* rounded up to 4K page boundary */
    struct _SECTION *Section;
} MMVAD, *PMMVAD;

#define MM_AVL_NODE_TO_VAD(Node)					\
    ((Node) != NULL ? CONTAINING_RECORD(Node, MMVAD, AvlNode) : NULL)

/*
 * A paging structure represents a capability to either a page,
 * a large page, or a page table. A paging structure has a unique
 * virtual address space associated with it, since to share a
 * page in seL4 between multiple threads, the capability to that
 * page must first be cloned. Mapping the same page cap twice is
 * an error.
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
typedef enum _PAGING_STRUCTURE_TYPE {
    PAGING_TYPE_PAGE = seL4_X86_4K,
    PAGING_TYPE_LARGE_PAGE = seL4_X86_LargePageObject,
    PAGING_TYPE_PAGE_TABLE = seL4_X86_PageTableObject,
    PAGING_TYPE_PAGE_DIRECTORY = seL4_X86_PageDirectoryObject,
    PAGING_TYPE_ROOT_PAGING_STRUCTURE = seL4_VSpaceObject,
#ifdef _M_IX86
    PAGING_TYPE_PDPT = 0,
    PAGING_TYPE_PML4 = 0,
#elif defined(_M_AMD64)
    PAGING_TYPE_PDPT = seL4_X86_PDPTObject,
    PAGING_TYPE_PML4 = seL4_X64_PML4Object,
#else
#error "Unsupported architecture"
#endif
} PAGING_STRUCTURE_TYPE;

#define PAGING_RIGHTS		seL4_CapRights_t
#define PAGING_ATTRIBUTES	seL4_X86_VMAttributes

typedef struct _PAGING_STRUCTURE {
    CAP_TREE_NODE TreeNode;
    MM_AVL_NODE AvlNode;
    struct _PAGING_STRUCTURE *SuperStructure;
    MM_AVL_TREE SubStructureTree;
    MWORD VSpaceCap;
    PAGING_STRUCTURE_TYPE Type;
    BOOLEAN Mapped;
    PAGING_RIGHTS Rights;
    PAGING_ATTRIBUTES Attributes;
} PAGING_STRUCTURE, *PPAGING_STRUCTURE;

#define MM_AVL_NODE_TO_PAGING_STRUCTURE(Node)					\
    ((Node) != NULL ? CONTAINING_RECORD(Node, PAGING_STRUCTURE, AvlNode) : NULL)

#define MM_RIGHTS_RW	(seL4_ReadWrite)

typedef ULONG WIN32_PROTECTION_MASK;
typedef PULONG PWIN32_PROTECTION_MASK;

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
    MM_AVL_TREE VadTree;
    PMMVAD CachedVad;		/* Speed up look up */
    PAGING_STRUCTURE RootPagingStructure;
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
    LIST_ENTRY SmallUntypedList; /* *Free* untyped's that are smaller than one page */
    LIST_ENTRY MediumUntypedList; /* *Free* untyped's at least one page but smaller than one large page */
    LIST_ENTRY LargeUntypedList;  /* *Free* untyped's at least one large page */
    MM_AVL_TREE RootUntypedForest; /* Root untyped forest organized by their starting phy addr.
				    * Note that RootUntypedForest represents both the cap derivation
				    * forest as well as the AVL tree of all untyped caps. */
    PUNTYPED CachedRootUntyped; /* Speed up look up */
} PHY_MEM_DESCRIPTOR, *PPHY_MEM_DESCRIPTOR;

typedef enum _MM_MEM_PRESSURE {
    MM_MEM_PRESSURE_SUFFICIENT_MEMORY,
    MM_MEM_PRESSURE_LOW_MEMORY,
    MM_MEM_PRESSURE_CRITICALLY_LOW_MEMORY
} MM_MEM_PRESSURE;

/*
 * Section object.
 *
 * A SECTION object describes the in-memory mapping of a FILE. The SECTION object
 * is managed by the object manager and exposed to the client processes (via an
 * instance handle). It is essentially a pointer into the actual IMAGE_SECTION_OBJECT
 * struct or DATA_SECTION_OBJECT struct. Since multiple SECTION objects can point
 * to the same FILE which can be mapped as image or data, the FILE_OBJECT contains
 * pointers to both IMAGE_SECTION_OBJECT and DATA_SECTION_OBJECT.
 *
 * Note the nomenclatures here are somewhat different from ELF/PE object format
 * and may be confusing. A PE file can have multiple sections (.text, .data, etc)
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
    MM_AVL_NODE BasedSectionNode; /* All SEC_BASED Sections are organized in an AVL tree */
    union {
	struct _IMAGE_SECTION_OBJECT *ImageSectionObject;
	struct _DATA_SECTION_OBJECT *DataSectionObject;
    };
    MMSECTION_FLAGS Flags;
} SECTION, *PSECTION;

typedef struct _IMAGE_SECTION_OBJECT {
    LIST_ENTRY SubSectionList;
    LONG NumSubSections;
    struct _FILE_OBJECT *FileObject;
    MWORD ImageBase;
    SECTION_IMAGE_INFORMATION ImageInformation;
} IMAGE_SECTION_OBJECT, *PIMAGE_SECTION_OBJECT;

typedef struct _DATA_SECTION_OBJECT {
    MWORD SectionSize;
    struct _FILE_OBJECT *FileObject;
} DATA_SECTION_OBJECT, *PDATA_SECTION_OBJECT;

/*
 * A subsection is a window of contiguous pages within a section. All
 * subsections that belong to a section are linked in its SubSectionList.
 */
typedef struct _SUBSECTION {
    PIMAGE_SECTION_OBJECT ImageSection;	/* Image section that this subsection belong to */
    LIST_ENTRY Link; /* Link for the owning image section's SubSectionList */
    UCHAR Name[IMAGE_SIZEOF_SHORT_NAME+1]; /* name of the PE section (.text, .data, etc) */
    ULONG SubSectionSize; /* Size of the subsection in memory, 4K aligned. */
    ULONG FileOffset; /* Offset from the start of the file, file aligned */
    ULONG RawDataSize;   /* Size of the subsection, file aligned */
    ULONG SubSectionBase; /* relative to the start of the owning section, 4K aligned */
    ULONG Characteristics; /* section characteristics in the PE image section table */
} SUBSECTION, *PSUBSECTION;

/*
 * Forward declarations
 */

/* init.c */
NTSTATUS MmInitSystem(IN seL4_BootInfo *bootinfo);

/* avltree.c */
VOID MmAvlDumpTree(PMM_AVL_TREE tree);
VOID MmAvlDumpTreeLinear(PMM_AVL_TREE tree);

/* cap.c */
VOID MmDbgDumpCapTreeNode(IN PCAP_TREE_NODE Node);
NTSTATUS MmAllocateCapRangeEx(IN PCNODE CNode,
			      OUT MWORD *StartCap,
			      IN LONG NumberRequested);
NTSTATUS MmDeallocateCapEx(IN PCNODE CNode,
			   IN MWORD Cap);
NTSTATUS MmCreateCNode(IN ULONG Log2Size,
		       OUT PCNODE *pCNode);
NTSTATUS MmDeleteCNode(PCNODE CNode);

static inline NTSTATUS MmAllocateCap(OUT MWORD *Cap)
{
    extern CNODE MiNtosCNode;
    return MmAllocateCapRangeEx(&MiNtosCNode, Cap, 1);
}

static inline NTSTATUS MmAllocateCapRange(OUT MWORD *StartCap,
					  IN LONG NumberRequested)
{
    extern CNODE MiNtosCNode;
    return MmAllocateCapRangeEx(&MiNtosCNode, StartCap, NumberRequested);
}

static inline NTSTATUS MmDeallocateCap(IN MWORD Cap)
{
    extern CNODE MiNtosCNode;
    return MmDeallocateCapEx(&MiNtosCNode, Cap);
}

/* untyped.c */
NTSTATUS MmRequestUntyped(IN LONG Log2Size,
			  OUT PUNTYPED *pUntyped);
NTSTATUS MmReleaseUntyped(IN PUNTYPED Untyped);
NTSTATUS MmRetypeIntoObject(IN PUNTYPED Untyped,
			    IN MWORD ObjType,
			    IN MWORD ObjBits,
			    OUT MWORD *ObjCap);
VOID MmDbgDumpUntypedInfo();

/* page.c */
MM_MEM_PRESSURE MmQueryMemoryPressure();
NTSTATUS MmCommitIoPageEx(IN PVIRT_ADDR_SPACE VaddrSpace,
			  IN MWORD PhyAddr,
			  IN MWORD VirtAddr,
			  IN PAGING_RIGHTS Rights,
			  OUT OPTIONAL PPAGING_STRUCTURE *pPage);
VOID MmDbgDumpPagingStructure(IN PPAGING_STRUCTURE Paging);

static inline NTSTATUS MmCommitIoPage(IN MWORD PhyAddr,
				      IN MWORD VirtAddr)
{
    extern VIRT_ADDR_SPACE MiNtosVaddrSpace;
    return MmCommitIoPageEx(&MiNtosVaddrSpace, PhyAddr, VirtAddr, MM_RIGHTS_RW, NULL);
}

/* section.c */
NTSTATUS MmCreateSection(IN struct _FILE_OBJECT *FileObject,
			 IN MWORD Attribute,
			 OUT PSECTION *SectionObject);
NTSTATUS MmMapViewOfSection(IN PVIRT_ADDR_SPACE VSpace,
			    IN PSECTION Section,
			    IN OUT MWORD *BaseAddress,
			    IN OUT MWORD *SectionOffset,
			    IN OUT MWORD *ViewSize);
VOID MmDbgDumpSection(IN PSECTION Section);

/* vaddr.c */
VOID MmInitializeVaddrSpace(IN PVIRT_ADDR_SPACE VaddrSpace,
			    IN MWORD VSpaceCap);
NTSTATUS MmAssignASID(IN PVIRT_ADDR_SPACE VaddrSpace);
NTSTATUS MmAllocatePrivateMemoryEx(IN PVIRT_ADDR_SPACE VSpace,
				   IN MWORD VirtAddr,
				   IN MWORD WindowSize,
				   IN MWORD AllocationType,
				   IN MWORD Protect);
NTSTATUS MmQueryVirtualAddress(IN PVIRT_ADDR_SPACE VSpace,
			       IN MWORD VirtAddr,
			       OUT PPAGING_STRUCTURE *pPage);
VOID MmDbgDumpVad(PMMVAD Vad);
VOID MmDbgDumpVSpace(PVIRT_ADDR_SPACE VSpace);

static inline NTSTATUS MmAllocatePrivateMemory(IN MWORD VirtAddr,
					       IN MWORD WindowSize)
{
    extern VIRT_ADDR_SPACE MiNtosVaddrSpace;
    return MmAllocatePrivateMemoryEx(&MiNtosVaddrSpace, VirtAddr, WindowSize,
				     MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES,
				     PAGE_READWRITE);
}
