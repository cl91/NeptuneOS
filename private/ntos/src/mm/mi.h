#pragma once

#include <nt.h>
#include <ntos.h>

#define ROOT_CNODE_LOG2SIZE	(CONFIG_ROOT_CNODE_SIZE_BITS)
#define LARGE_PN_SHIFT		(LARGE_PAGE_LOG2SIZE - PAGE_LOG2SIZE)

/* Information needed to initialize the Memory Management subcomponent,
 * including the Executive Pool */
typedef struct _MM_INIT_INFO {
    MWORD InitUntypedCap;
    MWORD InitUntypedPhyAddr;
    LONG InitUntypedLog2Size;
    MWORD RootCNodeFreeCapStart;
    MWORD UserStartPageNum;
    MWORD UserPageCapStart;
    MWORD NumUserPages;
    MWORD UserPagingStructureCapStart;
    MWORD NumUserPagingStructureCaps;
} MM_INIT_INFO, *PMM_INIT_INFO;

#define MiAllocatePoolEx(Var, Type, OnError)				\
    ExAllocatePoolEx(Var, Type, sizeof(Type), NTOS_MM_TAG, OnError)
#define MiAllocatePool(Var, Type)	MiAllocatePoolEx(Var, Type, {})

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
    assert(RootCap != NULL);
    assert(UsedMap != NULL);
    MiInitializeCapTreeNode(&Self->TreeNode, MM_CAP_TREE_NODE_CNODE,
			    RootCap, Parent);
    Self->Log2Size = Log2Size;
    Self->RecentFree = 1;
    Self->TotalUsed = 1;
    SetBit(UsedMap, 0);
    Self->UsedMap = UsedMap;
}

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
 * structure will be the child of the old paging structure
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

typedef struct _MM_PAGE {
    MM_AVL_NODE AvlNode;	/* must be first entry */
    MM_PAGING_STRUCTURE PagingStructure; /* must be second entry */
} MM_PAGE, *PMM_PAGE;

typedef struct _MM_LARGE_PAGE {
    MM_AVL_NODE AvlNode;	/* must be first entry. See MM_VAD */
    MM_PAGING_STRUCTURE PagingStructure; /* must be second entry */
} MM_LARGE_PAGE, *PMM_LARGE_PAGE;

typedef struct _MM_PAGE_TABLE {
    MM_AVL_NODE AvlNode;	/* must be first entry. See MM_VAD */
    MM_PAGING_STRUCTURE PagingStructure; /* must be second entry */
    MM_AVL_TREE MappedPages;  /* balanced tree for all mapped pages */
} MM_PAGE_TABLE, *PMM_PAGE_TABLE;

#define MM_RIGHTS_RW	(seL4_ReadWrite)

typedef ULONG WIN32_PROTECTION_MASK;
typedef PULONG PWIN32_PROTECTION_MASK;

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
				       MWORD StartPageNum,
				       MWORD NumPages)
{
    MiAvlInitializeNode(&Node->AvlNode, StartPageNum);
    Node->NumPages = NumPages;
    Node->FirstPageTable = NULL;
    Node->LastPageTable = NULL;
}


/*
 * Forward declarations.
 */

/* init.c */
extern MM_VADDR_SPACE MiNtosVaddrSpace;
extern MM_PHY_MEM MiPhyMemDescriptor;
extern MM_CNODE MiNtosCNode;
NTSTATUS MiSplitInitialUntyped(IN MWORD SrcCap,
			       IN LONG SrcLog2Size,
			       IN MWORD DestCap);
NTSTATUS MiInitRetypeIntoPage(IN MWORD Untyped,
			      IN MWORD PageCap,
			      IN MWORD Type);
NTSTATUS MiInitMapPage(IN PMM_INIT_INFO InitInfo,
		       IN MWORD Untyped,
		       IN MWORD PageCap,
		       IN MWORD Vaddr,
		       IN MWORD Type);

/* arch/init.c */
NTSTATUS MiInitMapInitialHeap(IN PMM_INIT_INFO InitInfo,
			      OUT LONG *PoolPages,
			      OUT MWORD *FreeCapStart);
NTSTATUS MiInitRecordUntypedAndPages(IN PMM_INIT_INFO InitInfo,
				     IN PMM_VAD ExPoolVad);
NTSTATUS MiInitRecordUserImagePaging(IN PMM_INIT_INFO InitInfo,
				     IN PMM_VAD UserImageVad);

/* untyped.c */
VOID MiInitializeUntyped(IN PMM_UNTYPED Untyped,
			 IN PMM_UNTYPED Parent,
			 IN MWORD Cap,
			 IN MWORD PhyAddr,
			 IN LONG Log2Size,
			 IN BOOLEAN IsDevice);
NTSTATUS MiSplitUntyped(IN PMM_UNTYPED SrcUntyped,
			OUT PMM_UNTYPED DestUntyped1,
			OUT PMM_UNTYPED DestUntyped2);
VOID MiInsertFreeUntyped(PMM_PHY_MEM PhyMem,
			 PMM_UNTYPED Untyped);
NTSTATUS MiRequestIoUntyped(IN PMM_PHY_MEM PhyMem,
			    IN MWORD PhyPageNum,
			    OUT PMM_UNTYPED *IoUntyped);
NTSTATUS MiInsertRootUntyped(IN PMM_PHY_MEM PhyMem,
			     IN PMM_UNTYPED RootUntyped);

/* avltree.c */
PMM_AVL_NODE MiAvlTreeFindNodeOrParent(IN PMM_AVL_TREE Tree,
				       IN MWORD Key);
VOID MiAvlTreeInsertNode(IN PMM_AVL_TREE Tree,
			 IN PMM_AVL_NODE Parent,
			 IN PMM_AVL_NODE Node);

/* vaddr.c */
NTSTATUS MiPageTableInsertPage(IN PMM_PAGE_TABLE PageTable,
			       IN PMM_PAGE Page);
NTSTATUS MiVspaceInsertVadNode(IN PMM_VADDR_SPACE Vspace,
			       IN PMM_VAD VadNode);
PMM_VAD MiVspaceFindVadNode(IN PMM_VADDR_SPACE Vspace,
			    IN MWORD StartPageNum,
			    IN MWORD NumPages);
PMM_AVL_NODE MiVspaceFindPageTableOrLargePage(IN PMM_VADDR_SPACE Vspace,
					      IN MWORD LargePageNum);
BOOLEAN MiPTNodeIsLargePage(PMM_AVL_NODE Node);
BOOLEAN MiPTNodeIsPageTable(PMM_AVL_NODE Node);
NTSTATUS MiVspaceInsertLargePage(IN PMM_VADDR_SPACE Vspace,
				 IN PMM_VAD Vad,
				 IN PMM_LARGE_PAGE LargePage);
NTSTATUS MiVspaceInsertPageTable(IN PMM_VADDR_SPACE Vspace,
				 IN PMM_VAD Vad,
				 IN PMM_PAGE_TABLE PageTable);
NTSTATUS MiPageTableInsertPage(IN PMM_PAGE_TABLE PageTable,
			       IN PMM_PAGE Page);
PMM_PAGE MiPageTableFindPage(IN PMM_PAGE_TABLE PageTable,
			     IN MWORD PageNum);

/* page.c */
VOID MiInitializePage(IN PMM_PAGE Page,
		      IN PMM_UNTYPED Parent,
		      IN PMM_VADDR_SPACE VaddrSpace,
		      IN MWORD Cap,
		      IN MWORD VirtPageNum,
		      IN BOOLEAN Mapped,
		      IN seL4_CapRights_t Rights);
VOID MiInitializeLargePage(IN PMM_LARGE_PAGE LargePage,
			   IN PMM_UNTYPED Parent,
			   IN PMM_VADDR_SPACE VaddrSpace,
			   IN MWORD Cap,
			   IN MWORD VirtPTNum,
			   IN BOOLEAN Mapped,
			   IN seL4_CapRights_t Rights);
VOID MiInitializePageTable(IN PMM_PAGE_TABLE PageTable,
			   IN PMM_UNTYPED Parent,
			   IN PMM_VADDR_SPACE VaddrSpace,
			   IN MWORD Cap,
			   IN MWORD VirtPTNum,
			   IN BOOLEAN Mapped);
