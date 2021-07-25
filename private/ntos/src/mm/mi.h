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

static inline VOID MiInitializeCapTreeNode(IN PCAP_TREE_NODE Self,
					   IN CAP_TREE_NODE_TYPE Type,
					   IN MWORD Cap,
					   IN OPTIONAL PCAP_TREE_NODE Parent)
{
    assert(Self != NULL);
    Self->Type = Type;
    Self->Cap = Cap;
    Self->Parent = Parent;
    InitializeListHead(&Self->ChildrenList);
    InitializeListHead(&Self->SiblingLink);
    if (Parent != NULL) {
	InsertTailList(&Parent->ChildrenList, &Self->SiblingLink);
    }
}

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
				     IN MWORD RootCap,
				     IN ULONG Log2Size,
				     IN OPTIONAL PCAP_TREE_NODE Parent,
				     IN MWORD *UsedMap)
{
    assert(Self != NULL);
    assert(RootCap != 0);
    assert(UsedMap != NULL);
    MiInitializeCapTreeNode(&Self->TreeNode, CAP_TREE_NODE_CNODE,
			    RootCap, Parent);
    Self->Log2Size = Log2Size;
    Self->RecentFree = 1;
    Self->TotalUsed = 1;
    SetBit(UsedMap, 0);
    Self->UsedMap = UsedMap;
}

static inline PUNTYPED MiTreeNodeToUntyped(PCAP_TREE_NODE TreeNode)
{
    return CONTAINING_RECORD(TreeNode, UNTYPED, TreeNode);
}

static inline VOID MiAvlInitializeNode(PMM_AVL_NODE Node,
				       MWORD Key)
{
    Node->Parent = 0;
    Node->LeftChild = Node->RightChild = NULL;
    Node->Key = Key;
    Node->ListEntry.Flink = Node->ListEntry.Blink = NULL;
}

static inline VOID MiAvlInitializeTree(PMM_AVL_TREE Tree)
{
    Tree->BalancedRoot = NULL;
    InitializeListHead(&Tree->NodeList);
}

static inline VOID MiInitializeVadNode(PMMVAD Node,
				       MWORD StartVaddr,
				       MWORD WindowSize)
{
    assert(IS_PAGE_ALIGNED(StartVaddr));
    assert(IS_PAGE_ALIGNED(WindowSize));
    MiAvlInitializeNode(&Node->AvlNode, StartVaddr);
    Node->Flags.Word = 0;
    Node->WindowSize = WindowSize;
    Node->Section = NULL;
}

#define LoopOverVadTree(Vad, VSpace, Statement)				\
    LoopOverList(_LoopOverVadTree_tmp_Node, &VSpace->VadTree.NodeList,	\
		 MM_AVL_NODE, ListEntry) {				\
    PMMVAD Vad = MM_AVL_NODE_TO_VAD(_LoopOverVadTree_tmp_Node);		\
    Statement; }


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
			 IN PUNTYPED Parent,
			 IN MWORD Cap,
			 IN MWORD PhyAddr,
			 IN LONG Log2Size,
			 IN BOOLEAN IsDevice);
NTSTATUS MiSplitUntypedCap(IN MWORD SrcCap,
			   IN LONG SrcLog2Size,
			   IN MWORD DestCap);
NTSTATUS MiSplitUntyped(IN PUNTYPED SrcUntyped,
			OUT PUNTYPED DestUntyped1,
			OUT PUNTYPED DestUntyped2);
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

/*
 * Returns TRUE if the supplied address is within the address range
 * specified by the address window
 */
static inline BOOLEAN MiAddrWindowContainsAddr(IN MWORD StartAddr,
					       IN MWORD WindowSize,
					       IN MWORD Addr)
{
    MWORD EndAddr = StartAddr + WindowSize;
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
PPAGING_STRUCTURE MiPagingFindSubstructure(IN PPAGING_STRUCTURE Paging,
					   IN MWORD VirtAddr);
NTSTATUS MiCommitPrivateMemory(IN PVIRT_ADDR_SPACE VaddrSpace,
			       IN MWORD VirtAddr,
			       IN MWORD Size,
			       IN PAGING_RIGHTS Rights,
			       IN BOOLEAN UseLargePage);

/* section.c */
NTSTATUS MiSectionInitialization();

/* vaddr.c */
NTSTATUS MiReserveVirtualMemory(IN PVIRT_ADDR_SPACE VSpace,
				IN MWORD VirtAddr,
				IN MWORD WindowSize,
				IN MWORD Attribute);
