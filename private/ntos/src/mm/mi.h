#pragma once

#include <nt.h>
#include <ntos.h>

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

static inline BOOLEAN MiCapTreeNodeHasChildren(IN PCAP_TREE_NODE Node)
{
    return !IsListEmpty(&Node->ChildrenList);
}

static inline ULONG MiCapTreeNodeChildrenCount(IN PCAP_TREE_NODE Node)
{
    return GetListLength(&Node->ChildrenList);
}

static inline PCAP_TREE_NODE MiCapTreeNodeGetFirstChild(IN PCAP_TREE_NODE Node)
{
    assert(MiCapTreeNodeHasChildren(Node));
    return CONTAINING_RECORD(Node->ChildrenList.Flink, CAP_TREE_NODE, SiblingLink);
}

static inline PCAP_TREE_NODE MiCapTreeNodeGetSecondChild(IN PCAP_TREE_NODE Node)
{
    assert(MiCapTreeNodeChildrenCount(Node) == 2);
    return CONTAINING_RECORD(Node->ChildrenList.Flink->Flink, CAP_TREE_NODE, SiblingLink);
}

#define MiCapTreeGetFirstChildTyped(Obj, Type)	(CONTAINING_RECORD(MiCapTreeNodeGetFirstChild(&(Obj)->TreeNode), Type, TreeNode))
#define MiCapTreeGetSecondChildTyped(Obj, Type)	(CONTAINING_RECORD(MiCapTreeNodeGetSecondChild(&(Obj)->TreeNode), Type, TreeNode))

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

#define TREE_NODE_TO_UNTYPED(Node) CONTAINING_RECORD(Node, UNTYPED, TreeNode)

static inline VOID MiAvlInitializeNode(PMM_AVL_NODE Node,
				       MWORD Key)
{
    Node->Parent = 0;
    Node->LeftChild = Node->RightChild = NULL;
    Node->Key = Key;
    Node->ListEntry.Flink = Node->ListEntry.Blink = NULL;
}

static inline VOID MiAvlInitializeTree(IN PMM_AVL_TREE Tree)
{
    Tree->BalancedRoot = NULL;
    InitializeListHead(&Tree->NodeList);
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
    MiAvlInitializeNode(&Node->AvlNode, StartVaddr);
    Node->VSpace = VSpace;
    Node->Flags = Flags;
    Node->WindowSize = WindowSize;
}

#define LoopOverVadTree(Vad, VSpace, Statement)				\
    LoopOverList(_LoopOverVadTree_tmp_Node, &VSpace->VadTree.NodeList,	\
		 MM_AVL_NODE, ListEntry) {				\
    PMMVAD Vad = MM_AVL_NODE_TO_VAD(_LoopOverVadTree_tmp_Node);		\
    Statement; }

/*
 * Returns the next node in the AVL tree, ordered linearly.
 *
 * If Node is the last node in the tree, returns NULL.
 */
static inline PMM_AVL_NODE MiAvlGetNextNode(IN PMM_AVL_TREE Tree,
					    IN PMM_AVL_NODE Node)
{
    assert(Tree != NULL);
    assert(Node != NULL);
    PLIST_ENTRY Flink = Node->ListEntry.Flink;
    if (Flink == &Tree->NodeList) {
	return NULL;
    }
    return LIST_ENTRY_TO_MM_AVL_NODE(Flink);
}

/*
 * Returns the previous node in the AVL tree, ordered linearly.
 *
 * If Node is the first node in the tree, returns NULL.
 */
static inline PMM_AVL_NODE MiAvlGetPrevNode(IN PMM_AVL_TREE Tree,
					    IN PMM_AVL_NODE Node)
{
    assert(Tree != NULL);
    assert(Node != NULL);
    PLIST_ENTRY Blink = Node->ListEntry.Blink;
    if (Blink == &Tree->NodeList) {
	return NULL;
    }
    return LIST_ENTRY_TO_MM_AVL_NODE(Blink);
}

static inline BOOLEAN MiAvlTreeIsEmpty(IN PMM_AVL_TREE Tree)
{
    assert(Tree != NULL);
    return Tree->BalancedRoot == NULL;
}

/*
 * Forward declarations.
 */

/* init.c */
extern VIRT_ADDR_SPACE MiNtosVaddrSpace;
extern PHY_MEM_DESCRIPTOR MiPhyMemDescriptor;
extern CNODE MiNtosCNode;

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

static inline BOOLEAN MiPagingTypeIsPage(IN PAGING_STRUCTURE_TYPE Type)
{
    return Type == PAGING_TYPE_PAGE;
}

/* vaddr.c */
VOID MiInitializeVSpace(IN PVIRT_ADDR_SPACE Self,
			IN PPAGING_STRUCTURE RootPagingStructure);
NTSTATUS MiCommitImageVad(IN PMMVAD Vad);
