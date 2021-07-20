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

static inline VOID MiInitializeCapTreeNode(IN PMM_CAP_TREE_NODE Self,
					   IN MM_CAP_TREE_NODE_TYPE Type,
					   IN MWORD Cap,
					   IN OPTIONAL PMM_CAP_TREE_NODE Parent)
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

static inline BOOLEAN MiCapTreeNodeHasChildren(IN PMM_CAP_TREE_NODE Node)
{
    return !IsListEmpty(&Node->ChildrenList);
}

static inline ULONG MiCapTreeNodeChildrenCount(IN PMM_CAP_TREE_NODE Node)
{
    return GetListLength(&Node->ChildrenList);
}

static inline PMM_CAP_TREE_NODE MiCapTreeNodeGetFirstChild(IN PMM_CAP_TREE_NODE Node)
{
    assert(MiCapTreeNodeHasChildren(Node));
    return CONTAINING_RECORD(Node->ChildrenList.Flink, MM_CAP_TREE_NODE, SiblingLink);
}

static inline PMM_CAP_TREE_NODE MiCapTreeNodeGetSecondChild(IN PMM_CAP_TREE_NODE Node)
{
    assert(MiCapTreeNodeChildrenCount(Node) == 2);
    return CONTAINING_RECORD(Node->ChildrenList.Flink->Flink, MM_CAP_TREE_NODE, SiblingLink);
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

    return (Map[WordOffset] & (1 << BitOffset)) != 0;
}

static inline VOID SetBit(MWORD *Map, ULONG Bit)
{
    ULONG WordOffset = Bit / MWORD_BITS;
    ULONG BitOffset = Bit % MWORD_BITS;

    Map[WordOffset] |= (1 << BitOffset);
}

static inline VOID ClearBit(MWORD *Map, ULONG Bit)
{
    ULONG WordOffset = Bit / MWORD_BITS;
    ULONG BitOffset = Bit % MWORD_BITS;

    Map[WordOffset] &= ~(1 << BitOffset);
}

/* Initialize an empty CNode. The zeroth slot is always
 * used since it represents the null capability.
 */
static inline VOID MiInitializeCNode(IN PMM_CNODE Self,
				     IN MWORD RootCap,
				     IN ULONG Log2Size,
				     IN OPTIONAL PMM_CAP_TREE_NODE Parent,
				     IN MWORD *UsedMap)
{
    assert(Self != NULL);
    assert(RootCap != 0);
    assert(UsedMap != NULL);
    MiInitializeCapTreeNode(&Self->TreeNode, MM_CAP_TREE_NODE_CNODE,
			    RootCap, Parent);
    Self->Log2Size = Log2Size;
    Self->RecentFree = 1;
    Self->TotalUsed = 1;
    SetBit(UsedMap, 0);
    Self->UsedMap = UsedMap;
}

static inline PMM_UNTYPED MiTreeNodeToUntyped(PMM_CAP_TREE_NODE TreeNode)
{
    return CONTAINING_RECORD(TreeNode, MM_UNTYPED, TreeNode);
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

static inline VOID MiInitializeVadNode(PMM_VAD Node,
				       MWORD StartVaddr,
				       MWORD WindowSize)
{
    assert(IS_PAGE_ALIGNED(StartVaddr));
    MiAvlInitializeNode(&Node->AvlNode, StartVaddr);
    Node->WindowSize = WindowSize;
}


/*
 * Forward declarations.
 */

/* init.c */
extern MM_VADDR_SPACE MiNtosVaddrSpace;
extern MM_PHY_MEM MiPhyMemDescriptor;
extern MM_CNODE MiNtosCNode;

/* untyped.c */
VOID MiInitializePhyMemDescriptor(PMM_PHY_MEM PhyMem);
VOID MiInitializeUntyped(IN PMM_UNTYPED Untyped,
			 IN PMM_UNTYPED Parent,
			 IN MWORD Cap,
			 IN MWORD PhyAddr,
			 IN LONG Log2Size,
			 IN BOOLEAN IsDevice);
NTSTATUS MiSplitUntypedCap(IN MWORD SrcCap,
			   IN LONG SrcLog2Size,
			   IN MWORD DestCap);
NTSTATUS MiSplitUntyped(IN PMM_UNTYPED SrcUntyped,
			OUT PMM_UNTYPED DestUntyped1,
			OUT PMM_UNTYPED DestUntyped2);
VOID MiInsertFreeUntyped(PMM_PHY_MEM PhyMem,
			 PMM_UNTYPED Untyped);
NTSTATUS MiRequestIoUntyped(IN PMM_PHY_MEM PhyMem,
			    IN MWORD PhyAddr,
			    OUT PMM_UNTYPED *IoUntyped);
NTSTATUS MiInsertRootUntyped(IN PMM_PHY_MEM PhyMem,
			     IN PMM_UNTYPED RootUntyped);

/* avltree.c */
PMM_AVL_NODE MiAvlTreeFindNodeOrParent(IN PMM_AVL_TREE Tree,
				       IN MWORD Key);
VOID MiAvlTreeInsertNode(IN PMM_AVL_TREE Tree,
			 IN PMM_AVL_NODE Parent,
			 IN PMM_AVL_NODE Node);

/*
 * Returns TRUE if the supplied address is within the address range
 * specified by the AVL node's key value and the supplied window size
 */
static inline BOOLEAN MiAvlNodeContainsAddr(IN PMM_AVL_NODE Node,
					    IN MWORD Size,
					    IN MWORD Addr)
{
    assert(Node != NULL);
    MWORD StartAddr = Node->Key;
    MWORD EndAddr = StartAddr + Size;
    return (Addr >= StartAddr) && (Addr < EndAddr);
}

/*
 * Returns TRUE if the supplied address window is fully contained within
 * the AVL node with the given size
 */
static inline BOOLEAN MiAvlNodeContainsAddrWindow(IN PMM_AVL_NODE Node,
						  IN MWORD NodeSize,
						  IN MWORD Addr,
						  IN MWORD WindowSize)
{
    assert(Node != NULL);
    MWORD EndNodeAddr = Node->Key + NodeSize;
    MWORD EndWindowAddr = Addr + WindowSize;
    /* Note here the equal signs are important */
    return (Addr >= Node->Key) && (EndWindowAddr <= EndNodeAddr);
}

/*
 * Returns TRUE if the supplied address window has overlap with
 * the AVL node of the given size
 */
static inline BOOLEAN MiAvlNodeOverlapsAddrWindow(IN PMM_AVL_NODE Node,
						  IN MWORD NodeSize,
						  IN MWORD Addr,
						  IN MWORD WindowSize)
{
    assert(Node != NULL);
    MWORD EndWindowAddr = Addr + WindowSize;
    /* Note here the equal signs are important */
    return MiAvlNodeContainsAddr(Node, NodeSize, Addr) ||
	MiAvlNodeContainsAddr(Node, NodeSize, EndWindowAddr-1);
}

/* page.c */
VOID MiInitializePagingStructure(IN PMM_PAGING_STRUCTURE Page,
				 IN PMM_CAP_TREE_NODE ParentNode,
				 IN PMM_PAGING_STRUCTURE ParentPagingStructure,
				 IN MWORD VSpaceCap,
				 IN MWORD Cap,
				 IN MWORD VirtAddr,
				 IN MM_PAGING_STRUCTURE_TYPE Type,
				 IN BOOLEAN Mapped,
				 IN MM_PAGING_RIGHTS Rights);
NTSTATUS MiCreatePagingStructure(IN MM_PAGING_STRUCTURE_TYPE Type,
				 IN PMM_UNTYPED Untyped,
				 IN MWORD VirtAddr,
				 IN MWORD VSpaceCap,
				 IN MM_PAGING_RIGHTS Rights,
				 OUT PMM_PAGING_STRUCTURE *pPaging);
NTSTATUS MiVSpaceInsertPagingStructure(IN PMM_VADDR_SPACE VSpace,
				       IN PMM_PAGING_STRUCTURE Paging);
