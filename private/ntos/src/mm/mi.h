#pragma once

#include <ntos.h>
#include <ntintsafe.h>

#define ROOT_CNODE_LOG2SIZE	(CONFIG_ROOT_CNODE_SIZE_BITS)
#define LOG2SIZE_PER_CNODE_SLOT	(MWORD_LOG2SIZE + 2)

#define MiAllocatePoolEx(Var, Type, OnError)				\
    ExAllocatePoolEx(Var, Type, sizeof(Type), NTOS_MM_TAG, OnError)
#define MiAllocatePool(Var, Type)	MiAllocatePoolEx(Var, Type, {})
#define MiAllocateArray(Var, Type, Size, OnError)			\
    ExAllocatePoolEx(Var, Type, sizeof(Type) * (Size), NTOS_MM_TAG, OnError)
#define MiFreePool(Var) ExFreePoolWithTag(Var, NTOS_MM_TAG)

static inline ULONG ModPow2(IN ULONG Address, IN ULONG Alignment)
{
    assert(IsPow2(Alignment));
    return Address & (Alignment - 1);
}

static inline BOOLEAN AlignUp(OUT PULONG AlignedAddress,
			      IN ULONG Address,
			      IN ULONG Alignment)
{
    ULONG nExcess = ModPow2(Address, Alignment);

    if(nExcess == 0)
    {
	*AlignedAddress = Address;
	return nExcess == 0;
    }
    else
	return Intsafe_AddULong32(AlignedAddress, Address, Alignment - nExcess);
}

static inline VOID MiCapTreeRemoveFromParent(IN PCAP_TREE_NODE Node)
{
    assert(Node->SiblingLink.Flink != NULL);
    assert(Node->SiblingLink.Blink != NULL);
    assert(!IsListEmpty(&Node->SiblingLink));
    RemoveEntryList(&Node->SiblingLink);
    Node->Parent = NULL;
}

static inline PCAP_TREE_NODE MiCapTreeNodeGetFirstChild(IN PCAP_TREE_NODE Node)
{
    assert(MmCapTreeNodeHasChildren(Node));
    return CONTAINING_RECORD(Node->ChildrenList.Flink, CAP_TREE_NODE, SiblingLink);
}

static inline PCAP_TREE_NODE MiCapTreeNodeGetSecondChild(IN PCAP_TREE_NODE Node)
{
    assert(MmCapTreeNodeChildrenCount(Node) == 2);
    return CONTAINING_RECORD(Node->ChildrenList.Flink->Flink, CAP_TREE_NODE, SiblingLink);
}

#define MiCapTreeGetFirstChildTyped(Obj, Type)	(CONTAINING_RECORD(MiCapTreeNodeGetFirstChild(&(Obj)->TreeNode), Type, TreeNode))
#define MiCapTreeGetSecondChildTyped(Obj, Type)	(CONTAINING_RECORD(MiCapTreeNodeGetSecondChild(&(Obj)->TreeNode), Type, TreeNode))

#define CapTreeLoopOverChildren(Child, Node)				\
    LoopOverList(Child, &(Node)->ChildrenList, CAP_TREE_NODE, SiblingLink)

static inline PCAP_TREE_NODE MiCapTreeGetNextSibling(IN PCAP_TREE_NODE Node)
{
    assert(Node->SiblingLink.Flink != NULL);
    assert(Node->SiblingLink.Blink != NULL);
    if (Node->Parent == NULL) {
	return NULL;
    }
    assert(!IsListEmpty(&Node->SiblingLink));
    assert(GetListLength(&Node->Parent->ChildrenList) == GetListLength(&Node->SiblingLink));
    PLIST_ENTRY NextNode = Node->SiblingLink.Flink;
    if (NextNode == &Node->Parent->ChildrenList) {
	NextNode = NextNode->Flink;
    }
    if (NextNode == &Node->Parent->ChildrenList) {
	return NULL;
    }
    return CONTAINING_RECORD(NextNode, CAP_TREE_NODE, SiblingLink);
}

/* Initialize an empty CNode. The zeroth slot is always
 * used since it represents the null capability.
 */
static inline VOID MiInitializeCNode(IN PCNODE Self,
				     IN MWORD Cap,
				     IN ULONG Log2Size,
				     IN ULONG Depth,
				     IN PCNODE CSpace,
				     IN OPTIONAL PCAP_TREE_NODE Parent,
				     IN MWORD *UsedMap)
{
    assert(Self != NULL);
    assert(UsedMap != NULL);
    MmInitializeCapTreeNode(&Self->TreeNode, CAP_TREE_NODE_CNODE,
			    Cap, CSpace, Parent);
    Self->Log2Size = Log2Size;
    Self->Depth = Depth;
    Self->RecentFree = 1;
    Self->TotalUsed = 1;
    SetBit(UsedMap, 0);
    Self->UsedMap = UsedMap;
}

/*
 * Note: Node must point to zeroed-memory!
 */
static inline VOID MiInitializeVadNode(IN PMMVAD Node,
				       IN PVIRT_ADDR_SPACE VSpace,
				       IN MWORD StartVaddr,
				       IN MWORD WindowSize,
				       IN MMVAD_FLAGS Flags)
{
    assert(Node != NULL);
    assert(VSpace != NULL);
    assert(IS_PAGE_ALIGNED(WindowSize));
    assert(IS_PAGE_ALIGNED(StartVaddr));
    AvlInitializeNode(&Node->AvlNode, StartVaddr);
    Node->VSpace = VSpace;
    Node->Flags = Flags;
    Node->WindowSize = WindowSize;
}

/* IMPORTANT: You cannot use this macro if you want to delete the Vad! */
#define LoopOverVadTree(Vad, VSpace, Statement)				\
    for (PAVL_NODE Node = AvlGetFirstNode(&VSpace->VadTree);		\
	 Node != NULL; Node = AvlGetNextNode(Node)) {			\
	PMMVAD Vad = AVL_NODE_TO_VAD(Node);				\
	Statement;							\
    }

/*
 * Creation context for the section object creation routine
 */
typedef struct _SECTION_OBJ_CREATE_CONTEXT {
    PIO_FILE_OBJECT FileObject;
    ULONG PageProtection;
    ULONG Attributes;
    BOOLEAN PhysicalMapping;
} SECTION_OBJ_CREATE_CONTEXT, *PSECTION_OBJ_CREATE_CONTEXT;

/*
 * Forward declarations.
 */

/* init.c */
extern VIRT_ADDR_SPACE MiNtosVaddrSpace;
extern PHY_MEM_DESCRIPTOR MiPhyMemDescriptor;
extern CNODE MiNtosCNode;

/* cap.c */
VOID MiCapTreeRevokeNode(IN PCAP_TREE_NODE Node);

/* untyped.c */
VOID MiInitializePhyMemDescriptor(PPHY_MEM_DESCRIPTOR PhyMem);
VOID MiInitializeUntyped(IN PUNTYPED Untyped,
			 IN PCNODE CSpace,
			 IN OPTIONAL PUNTYPED Parent,
			 IN MWORD Cap,
			 IN MWORD PhyAddr,
			 IN LONG Log2Size,
			 IN BOOLEAN IsDevice);
NTSTATUS MiSplitUntypedCap(IN MWORD SrcCap,
			   IN LONG SrcLog2Size,
			   IN MWORD DestCSpace,
			   IN MWORD DestCap);
VOID MiInsertFreeUntyped(PPHY_MEM_DESCRIPTOR PhyMem,
			 PUNTYPED Untyped);
NTSTATUS MiGetUntypedAtPhyAddr(IN PPHY_MEM_DESCRIPTOR PhyMem,
			       IN MWORD PhyAddr,
			       IN LONG Log2Size,
			       OUT PUNTYPED *Untyped);
NTSTATUS MiInsertRootUntyped(IN PPHY_MEM_DESCRIPTOR PhyMem,
			     IN PUNTYPED RootUntyped);

/* Returns TRUE if the untyped is in one of the free lists */
static inline BOOLEAN MiUntypedIsInFreeLists(IN PUNTYPED Untyped)
{
    return ListHasEntry(&MiPhyMemDescriptor.LowMemUntypedList, &Untyped->FreeListEntry) ||
	ListHasEntry(&MiPhyMemDescriptor.SmallUntypedList, &Untyped->FreeListEntry) ||
	ListHasEntry(&MiPhyMemDescriptor.MediumUntypedList, &Untyped->FreeListEntry) ||
	ListHasEntry(&MiPhyMemDescriptor.LargeUntypedList, &Untyped->FreeListEntry);
}

/* page.c */
VOID MiInitializePagingStructure(IN PPAGING_STRUCTURE Page,
				 IN PCAP_TREE_NODE ParentNode,
				 IN PPAGING_STRUCTURE ParentPagingStructure,
				 IN MWORD VSpaceCap,
				 IN MWORD Cap,
				 IN MWORD VirtAddr,
				 IN PAGING_STRUCTURE_TYPE Type,
				 IN BOOLEAN Mapped,
				 IN PAGING_RIGHTS Rights,
    				 IN PAGING_ATTRIBUTES Attributes);
NTSTATUS MiCreatePagingStructure(IN PAGING_STRUCTURE_TYPE Type,
				 IN PUNTYPED Untyped,
				 IN PPAGING_STRUCTURE ParentPaging,
				 IN MWORD VirtAddr,
				 IN MWORD VSpaceCap,
				 IN PAGING_RIGHTS Rights,
				 IN PAGING_ATTRIBUTES Attributes,
				 OUT PPAGING_STRUCTURE *pPaging);
NTSTATUS MiVSpaceInsertPagingStructure(IN PVIRT_ADDR_SPACE VSpace,
				       IN PPAGING_STRUCTURE Paging);
PPAGING_STRUCTURE MiQueryVirtualAddress(IN PVIRT_ADDR_SPACE VSpace,
					IN MWORD VirtAddr);
MWORD MiGetPhysicalAddress(IN PPAGING_STRUCTURE Page);
PPAGING_STRUCTURE MiGetFirstPage(IN PPAGING_STRUCTURE Page);
PPAGING_STRUCTURE MiGetNextPagingStructure(IN PPAGING_STRUCTURE Page);
NTSTATUS MiMapIoMemory(IN PVIRT_ADDR_SPACE VSpace,
		       IN MWORD PhyAddr,
		       IN MWORD VirtAddr,
		       IN MWORD WindowSize,
		       IN PAGING_RIGHTS Rights,
		       IN PAGING_ATTRIBUTES Attributes,
		       IN BOOLEAN LargePage,
		       IN BOOLEAN IgnoreConflict);
VOID MiDeletePage(IN PPAGING_STRUCTURE Page);

static inline BOOLEAN MiPagingTypeIsRoot(IN PAGING_STRUCTURE_TYPE Type)
{
    return Type == PAGING_TYPE_ROOT_PAGING_STRUCTURE;
}

static inline BOOLEAN MiPagingTypeIsPage(IN PAGING_STRUCTURE_TYPE Type)
{
    return Type == PAGING_TYPE_PAGE;
}

static inline BOOLEAN MiPagingTypeIsLargePage(IN PAGING_STRUCTURE_TYPE Type)
{
    return Type == PAGING_TYPE_LARGE_PAGE;
}

static inline BOOLEAN MiPagingTypeIsPageOrLargePage(IN PAGING_STRUCTURE_TYPE Type)
{
    return Type == PAGING_TYPE_PAGE || Type == PAGING_TYPE_LARGE_PAGE;
}

/*
 * Returns the type of the seL4 kernel object representing the paging structure
 * that is one layer below the specified paging structure. In other words, for page
 * tables we return page, etc.
 *
 * Note that multiple paging structure types can share the same super-structure
 * (for instance, both page tables and large pages have page directory as parent),
 * and MiPagingSubStructureType returns the intermediate mapping structure (ie.
 * page table, page directory, and PDPT), not the large/huge page types.
 */
static inline PAGING_STRUCTURE_TYPE MiPagingSubStructureType(PAGING_STRUCTURE_TYPE Type)
{
    if (Type == PAGING_TYPE_PAGE_TABLE) {
	return PAGING_TYPE_PAGE;
    } else if (Type == PAGING_TYPE_PAGE_DIRECTORY) {
	return PAGING_TYPE_PAGE_TABLE;
    } else if (Type == PAGING_TYPE_PDPT) {
	return PAGING_TYPE_PAGE_DIRECTORY;
    } else if (Type == PAGING_TYPE_PML4) {
	return PAGING_TYPE_PDPT;
    }
    assert(FALSE);
    return 0;
}

/*
 * Returns the log2size of the address window that the paging structure represents
 */
static inline LONG MiPagingWindowLog2Size(IN PAGING_STRUCTURE_TYPE Type)
{
    if (Type == PAGING_TYPE_PAGE) {
	return PAGE_LOG2SIZE;
    } else if (Type == PAGING_TYPE_LARGE_PAGE) {
	return LARGE_PAGE_LOG2SIZE;
    } else if (Type == PAGING_TYPE_PAGE_TABLE) {
	return PAGE_TABLE_WINDOW_LOG2SIZE;
    } else if (Type == PAGING_TYPE_PAGE_DIRECTORY) {
	return PAGE_DIRECTORY_WINDOW_LOG2SIZE;
    } else if (Type == PAGING_TYPE_PDPT) {
	return PDPT_WINDOW_LOG2SIZE;
    } else if (Type == PAGING_TYPE_PML4) {
	return PML4_WINDOW_LOG2SIZE;
    }
    assert(FALSE);
    return 0;
}

/*
 * Returns the address window size of the paging structure
 */
static inline MWORD MiPagingWindowSize(IN PAGING_STRUCTURE_TYPE Type)
{
    return 1ULL << MiPagingWindowLog2Size(Type);
}

/*
 * Returns TRUE if the address window that the paging structure represents
 * contains the given virtual address
 */
static inline BOOLEAN MiPagingStructureContainsAddr(IN PPAGING_STRUCTURE Paging,
						    IN MWORD VirtAddr)
{
    return AvlNodeContainsAddr(&Paging->AvlNode,
			       MiPagingWindowSize(Paging->Type), VirtAddr);
}

/*
 * Sanitize the virtual address such that it is aligned with
 * the boundary of the address window of the paging structure
 */
static inline MWORD MiSanitizeAlignment(IN PAGING_STRUCTURE_TYPE Type,
					IN MWORD VirtAddr)
{
    return VirtAddr & ~(MiPagingWindowSize(Type) - 1);
}

#define ASSERT_ALIGNMENT(Page)						\
    assert(MiSanitizeAlignment(Page->Type, Page->AvlNode.Key) == Page->AvlNode.Key)

/* vaddr.c */
VOID MiInitializeVSpace(IN PVIRT_ADDR_SPACE Self,
			IN PPAGING_STRUCTURE RootPagingStructure);
VOID MiUncommitWindow(IN PVIRT_ADDR_SPACE VSpace,
		      IN OUT MWORD *StartAddr,
		      IN OUT MWORD *WindowSize);
