#pragma once

#include <nt.h>
#include <ntos.h>

/* Information needed to initialize the Memory Management subcomponent,
 * including the Executive Pool */
typedef struct _MM_INIT_INFO {
    MWORD InitVSpaceCap;
    MWORD InitUntypedCap;
    MWORD InitUntypedPhyAddr;
    LONG InitUntypedLog2Size;
    MWORD RootCNodeCap;
    LONG RootCNodeLog2Size;
    MWORD RootCNodeFreeCapStart;
    MWORD UserStartPageNum;
    MWORD UserPageCapStart;
    MWORD NumUserPages;
    MWORD UserPagingStructureCapStart;
    MWORD NumUserPagingStructureCaps;
} MM_INIT_INFO, *PMM_INIT_INFO;

#define MiAllocatePool(Var, Type)					\
    Type *Var = (Type *)ExAllocatePoolWithTag(sizeof(Type), NTOS_MM_TAG); \
    if ((Var) == NULL) { return STATUS_NTOS_OUT_OF_MEMORY; }

/* init.c */
extern MM_VADDR_SPACE MiNtosVaddrSpace;
extern MM_PHY_MEM MiPhyMemDescriptor;
extern MM_CAPSPACE MiNtosCapSpace;
NTSTATUS MiSplitInitialUntyped(IN MWORD RootCap,
			       IN MWORD SrcCap,
			       IN LONG SrcLog2Size,
			       IN MWORD DestCap);
NTSTATUS MiInitRetypeIntoPage(IN MWORD RootCap,
			      IN MWORD Untyped,
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
			 IN BOOLEAN IsLeft,
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

static inline VOID MiAvlInitializeTree(PMM_AVL_TREE Tree)
{
    Tree->BalancedRoot = NULL;
    InitializeListHead(&Tree->NodeList);
}

static inline VOID MiAvlInitializeNode(PMM_AVL_NODE Node,
				       MWORD Key)
{
    Node->Parent = 0;
    Node->LeftChild = Node->RightChild = NULL;
    Node->Key = Key;
    Node->ListEntry.Flink = Node->ListEntry.Blink = NULL;
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
