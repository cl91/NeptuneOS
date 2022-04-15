#pragma once

#include <nt.h>
#include <ntos.h>

/* Change this to 0 to enable debug tracing */
#if 1
#undef DbgTrace
#define DbgTrace(...)
#define DbgPrint(...)
#endif

#define ROOT_CNODE_LOG2SIZE	(CONFIG_ROOT_CNODE_SIZE_BITS)
#define LOG2SIZE_PER_CNODE_SLOT	(MWORD_LOG2SIZE + 2)

/* Information needed to initialize the Memory Management subcomponent,
 * including the Executive Pool */
typedef struct _MM_INIT_INFO {
    MWORD InitUntypedCap;
    MWORD InitUntypedPhyAddr;
    LONG InitUntypedLog2Size;
    MWORD RootCNodeFreeCapStart;
    MWORD UserImageStartVirtAddr;
    MWORD UserImageFrameCapStart;
    MWORD NumUserImageFrames;
    MWORD UserPagingStructureCapStart;
    MWORD NumUserPagingStructureCaps;
} MM_INIT_INFO, *PMM_INIT_INFO;

#define MiAllocatePoolEx(Var, Type, OnError)				\
    ExAllocatePoolEx(Var, Type, sizeof(Type), NTOS_MM_TAG, OnError)
#define MiAllocatePool(Var, Type)	MiAllocatePoolEx(Var, Type, {})
#define MiAllocateArray(Var, Type, Size, OnError)			\
    ExAllocatePoolEx(Var, Type, sizeof(Type) * (Size), NTOS_MM_TAG, OnError)
#define MiFreePool(Var) ExFreePoolWithTag(Var, NTOS_MM_TAG)

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

static inline PCAP_TREE_NODE MiCapTreeGetNextSibling(IN PCAP_TREE_NODE Node)
{
    assert(Node->SiblingLink.Flink != NULL);
    assert(Node->SiblingLink.Blink != NULL);
    if (Node->Parent == NULL) {
	return NULL;
    }
    assert(!IsListEmpty(&Node->SiblingLink));
    if (Node->SiblingLink.Flink == &Node->Parent->ChildrenList) {
	return NULL;
    }
    return CONTAINING_RECORD(Node->SiblingLink.Flink, CAP_TREE_NODE, SiblingLink);
}

/*
 * Helper functions for MWORD array as bitmaps
 */
static inline BOOLEAN GetBit(MWORD *Map, ULONG Bit)
{
    ULONG WordOffset = Bit / MWORD_BITS;
    ULONG BitOffset = Bit % MWORD_BITS;

    return (Map[WordOffset] & (1ULL << BitOffset)) != 0;
}

static inline VOID SetBit(MWORD *Map, ULONG Bit)
{
    ULONG WordOffset = Bit / MWORD_BITS;
    ULONG BitOffset = Bit % MWORD_BITS;

    Map[WordOffset] |= (1ULL << BitOffset);
}

static inline VOID ClearBit(MWORD *Map, ULONG Bit)
{
    ULONG WordOffset = Bit / MWORD_BITS;
    ULONG BitOffset = Bit % MWORD_BITS;

    Map[WordOffset] &= ~(1ULL << BitOffset);
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
    MmAvlInitializeNode(&Node->AvlNode, StartVaddr);
    Node->VSpace = VSpace;
    Node->Flags = Flags;
    Node->WindowSize = WindowSize;
}

#define LoopOverVadTree(Vad, VSpace, Statement)				\
    for (PMM_AVL_NODE Node = MiAvlGetFirstNode(&VSpace->VadTree);	\
	 Node != NULL; Node = MiAvlGetNextNode(Node)) {			\
	PMMVAD Vad = MM_AVL_NODE_TO_VAD(Node);				\
	Statement;							\
    }

static inline PMM_AVL_NODE MiAvlGetParent(PMM_AVL_NODE Node)
{
    MWORD ParentWord = Node->Parent;
    ParentWord &= ~((MWORD) 0x3ULL);
    return (PMM_AVL_NODE) ParentWord;
}

static inline BOOLEAN MiAvlIsRightChild(PMM_AVL_NODE Node)
{
    PMM_AVL_NODE Parent = MiAvlGetParent(Node);
    assert(Parent != NULL);
    return Parent->RightChild == Node;
}

static inline BOOLEAN MiAvlIsLeftChild(PMM_AVL_NODE Node)
{
    PMM_AVL_NODE Parent = MiAvlGetParent(Node);
    assert(Parent != NULL);
    return Parent->LeftChild == Node;
}

/*
 * Returns the next node in the AVL tree, ordered linearly.
 *
 * If Node is the last node in the tree, returns NULL.
 */
static inline PMM_AVL_NODE MiAvlGetNextNode(IN PMM_AVL_NODE Node)
{
    assert(Node != NULL);
    MWORD Key = Node->Key;
    if (Node->RightChild == NULL) {
	while (MiAvlGetParent(Node) != NULL) {
	    Node = MiAvlGetParent(Node);
	    assert(Node->Key != Key);
	    if (Node->Key > Key) {
		return Node;
	    }
	}
	return NULL;
    }
    Node = Node->RightChild;
    assert(Node != NULL);
    while (Node->LeftChild != NULL) {
	Node = Node->LeftChild;
    }
    return Node;
}

/*
 * Returns the previous node in the AVL tree, ordered linearly.
 *
 * If Node is the first node in the tree, returns NULL.
 */
static inline PMM_AVL_NODE MiAvlGetPrevNode(IN PMM_AVL_NODE Node)
{
    assert(Node != NULL);
    MWORD Key = Node->Key;
    if (Node->LeftChild == NULL) {
	while (MiAvlGetParent(Node) != NULL) {
	    Node = MiAvlGetParent(Node);
	    assert(Node->Key != Key);
	    if (Node->Key < Key) {
		return Node;
	    }
	}
	return NULL;
    }
    Node = Node->LeftChild;
    while (Node->RightChild != NULL) {
	Node = Node->RightChild;
    }
    return Node;
}

static inline BOOLEAN MiAvlTreeIsEmpty(IN PMM_AVL_TREE Tree)
{
    assert(Tree != NULL);
    return Tree->BalancedRoot == NULL;
}

static inline PMM_AVL_NODE MiAvlGetFirstNode(IN PMM_AVL_TREE Tree)
{
    PMM_AVL_NODE Node = Tree->BalancedRoot;
    if (Node == NULL) {
	return NULL;
    }
    while (Node->LeftChild != NULL) {
	Node = Node->LeftChild;
    }
    return Node;
}

static inline PMM_AVL_NODE MiAvlGetLastNode(IN PMM_AVL_TREE Tree)
{
    PMM_AVL_NODE Node = Tree->BalancedRoot;
    if (Node == NULL) {
	return NULL;
    }
    while (Node->RightChild != NULL) {
	DbgTrace("Node %p key 0x%zx RightChild %p key 0x%zx\n", Node, Node->Key,
		 Node->RightChild, Node->RightChild->Key);
	Node = Node->RightChild;
    }
    return Node;
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
NTSTATUS MiRequestIoUntyped(IN PPHY_MEM_DESCRIPTOR PhyMem,
			    IN MWORD PhyAddr,
			    OUT PUNTYPED *IoUntyped);
NTSTATUS MiInsertRootUntyped(IN PPHY_MEM_DESCRIPTOR PhyMem,
			     IN PUNTYPED RootUntyped);

/* avltree.c */
PMM_AVL_NODE MiAvlTreeFindNodeOrParent(IN PMM_AVL_TREE Tree,
				       IN MWORD Key);
PMM_AVL_NODE MiAvlTreeFindNodeOrPrev(IN PMM_AVL_TREE Tree,
				     IN MWORD Key);
VOID MiAvlTreeInsertNode(IN PMM_AVL_TREE Tree,
			 IN PMM_AVL_NODE Parent,
			 IN PMM_AVL_NODE Node);
VOID MiAvlTreeRemoveNode(IN PMM_AVL_TREE Tree,
			 IN PMM_AVL_NODE Node);

/*
 * Returns TRUE if the supplied address is within the address range
 * specified by the address window
 */
static inline BOOLEAN MiAddrWindowContainsAddr(IN MWORD StartAddr,
					       IN MWORD WindowSize,
					       IN MWORD Addr)
{
    MWORD EndAddr = StartAddr + WindowSize;
    assert(EndAddr > StartAddr);
    return (Addr >= StartAddr) && (Addr < EndAddr);
}

/*
 * Returns TRUE if the supplied address is within the address range
 * specified by the AVL node's key value and the supplied window size
 */
static inline BOOLEAN MiAvlNodeContainsAddr(IN PMM_AVL_NODE Node,
					    IN MWORD Size,
					    IN MWORD Addr)
{
    assert(Node != NULL);
    return MiAddrWindowContainsAddr(Node->Key, Size, Addr);
}

/*
 * Returns TRUE if the supplied address window has overlap with
 * the AVL node of the given size, ie. the intersection of the set
 * [Node, Node+NodeSize) with the set [Addr, Addr+WindowSize) is
 * non-empty in \mathbb{Z}.
 */
static inline BOOLEAN MiAvlNodeOverlapsAddrWindow(IN PMM_AVL_NODE Node,
						  IN MWORD NodeSize,
						  IN MWORD Addr,
						  IN MWORD WindowSize)
{
    assert(Node != NULL);
    return MiAvlNodeContainsAddr(Node, NodeSize, Addr) ||
	MiAvlNodeContainsAddr(Node, NodeSize, Addr + WindowSize - 1) ||
	MiAddrWindowContainsAddr(Addr, WindowSize, Node->Key) ||
	MiAddrWindowContainsAddr(Addr, WindowSize, Node->Key + NodeSize - 1);
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
				 IN PAGING_RIGHTS Rights);
NTSTATUS MiCreatePagingStructure(IN PAGING_STRUCTURE_TYPE Type,
				 IN PUNTYPED Untyped,
				 IN PPAGING_STRUCTURE ParentPaging,
				 IN MWORD VirtAddr,
				 IN MWORD VSpaceCap,
				 IN PAGING_RIGHTS Rights,
				 OUT PPAGING_STRUCTURE *pPaging);
NTSTATUS MiVSpaceInsertPagingStructure(IN PVIRT_ADDR_SPACE VSpace,
				       IN PPAGING_STRUCTURE Paging);
PPAGING_STRUCTURE MiQueryVirtualAddress(IN PVIRT_ADDR_SPACE VSpace,
					IN MWORD VirtAddr);
PPAGING_STRUCTURE MiGetFirstPage(IN PPAGING_STRUCTURE Page);
PPAGING_STRUCTURE MiGetNextPagingStructure(IN PPAGING_STRUCTURE Page);
NTSTATUS MiCommitOwnedMemory(IN PVIRT_ADDR_SPACE VSpace,
			     IN MWORD StartAddr,
			     IN MWORD WindowSize,
			     IN PAGING_RIGHTS Rights,
			     IN BOOLEAN UseLargePages,
			     IN OPTIONAL PVOID DataBuffer,
			     IN OPTIONAL MWORD BufferSize);
NTSTATUS MiMapMirroredMemory(IN PVIRT_ADDR_SPACE OwnerVSpace,
			     IN MWORD OwnerStartAddr,
			     IN PVIRT_ADDR_SPACE ViewerVSpace,
			     IN MWORD ViewerStartAddr,
			     IN MWORD WindowSize,
			     IN PAGING_RIGHTS NewRights);
NTSTATUS MiCommitIoPage(IN PVIRT_ADDR_SPACE VSpace,
			IN MWORD PhyAddr,
			IN MWORD VirtAddr,
			IN PAGING_RIGHTS Rights);
VOID MiDeletePage(IN PPAGING_STRUCTURE Page);

static inline BOOLEAN MiPagingTypeIsRoot(IN PAGING_STRUCTURE_TYPE Type)
{
    return Type == PAGING_TYPE_ROOT_PAGING_STRUCTURE;
}

static inline BOOLEAN MiPagingTypeIsPage(IN PAGING_STRUCTURE_TYPE Type)
{
    return Type == PAGING_TYPE_PAGE;
}

static inline BOOLEAN MiPagingTypeIsPageOrLargePage(IN PAGING_STRUCTURE_TYPE Type)
{
    return Type == PAGING_TYPE_PAGE || Type == PAGING_TYPE_LARGE_PAGE;
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

/* vaddr.c */
VOID MiInitializeVSpace(IN PVIRT_ADDR_SPACE Self,
			IN PPAGING_STRUCTURE RootPagingStructure);
NTSTATUS MiCommitImageVad(IN PMMVAD Vad);
