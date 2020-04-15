#pragma once

#include <nt.h>
#include <ntos.h>

/* init.c */
NTSTATUS MiSplitInitialUntyped(IN MWORD RootCap,
			       IN MWORD SrcCap,
			       IN LONG SrcLog2Size,
			       IN MWORD DestCap);
NTSTATUS MiInitRetypeIntoPage(IN MWORD RootCap,
			      IN MWORD Untyped,
			      IN MWORD PageCap,
			      IN MWORD Type);
NTSTATUS MiInitMapPage(IN PMM_INIT_INFO_CLASS InitInfo,
		       IN MWORD Untyped,
		       IN MWORD PageCap,
		       IN MWORD Vaddr,
		       IN MWORD Type);
VOID MiInitializeUntyped(IN PMM_UNTYPED Untyped,
			 IN PMM_UNTYPED Parent,
			 IN PMM_VADDR_SPACE VaddrSpace,
			 IN MWORD Cap,
			 IN LONG Log2Size);
VOID MiInitHeapPagingStructure(IN PMM_PAGING_STRUCTURE Page,
			       IN PMM_UNTYPED Parent,
			       IN PMM_VADDR_SPACE VaddrSpace,
			       IN MWORD Cap,
			       IN MWORD Vaddr,
			       IN MM_PAGING_STRUCTURE_TYPE Type,
			       IN PMM_INIT_INFO_CLASS InitInfo);

/* arch/init.c */
NTSTATUS MiInitMapInitialHeap(IN PMM_INIT_INFO_CLASS InitInfo,
			      OUT LONG *PoolPages,
			      OUT MWORD *FreeCapStart);
NTSTATUS MiInitHeapVad(IN PMM_INIT_INFO_CLASS InitInfo,
		       IN PMM_VADDR_SPACE VaddrSpace,
		       IN PMM_VAD ExPoolVad);

/* cap.c */
NTSTATUS MiCapSpaceAllocCaps(IN PMM_CAPSPACE CapSpace,
			     OUT MWORD *StartCap,
			     IN LONG NumberRequested);
NTSTATUS MiCapSpaceDeallocCap(IN PMM_CAPSPACE CapSpace,
			      IN MWORD Cap);

static inline NTSTATUS
MiCapSpaceAllocCap(IN PMM_CAPSPACE CapSpace,
		   OUT MWORD *Cap)
{
    return MiCapSpaceAllocCaps(CapSpace, Cap, 1);
}

/* untyped.c */
NTSTATUS MiSplitUntyped(IN PMM_UNTYPED SrcUntyped,
			OUT PMM_UNTYPED DestUntyped1,
			OUT PMM_UNTYPED DestUntyped2);
VOID MiInsertFreeUntyped(PMM_VADDR_SPACE VaddrSpace,
			 PMM_UNTYPED Untyped);
NTSTATUS MiRequestUntyped(IN PMM_VADDR_SPACE VaddrSpace,
			  IN LONG Log2Size,
			  OUT PMM_UNTYPED *Untyped);

/* page.c */
NTSTATUS MiMapPagingStructure(PMM_PAGING_STRUCTURE Page);

#define MiAllocatePool(Var, Type)					\
    Type *Var = (Type *)ExAllocatePoolWithTag(sizeof(Type), NTOS_MM_TAG); \
    if ((Var) == NULL) { return STATUS_NTOS_OUT_OF_MEMORY; }

/* avltree.c */
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
NTSTATUS MiVspaceInsertIoUntyped(IN PMM_VADDR_SPACE VaddrSpace,
				 IN PMM_IO_UNTYPED IoUntyped,
				 IN MWORD PhyAddr);

static inline VOID MiAvlInitializeTree(PMM_AVL_TREE Tree)
{
    Tree->BalancedRoot = NULL;
    InitializeListHead(&Tree->NodeList);
}

static inline VOID MiAvlInitializeNode(PMM_AVL_NODE Node,
				       MWORD PageNum)
{
    Node->Parent = 0;
    Node->LeftChild = Node->RightChild = NULL;
    Node->Key = PageNum;
    Node->ListEntry.Flink = Node->ListEntry.Blink = NULL;
}

static inline VOID MiInitializePageNode(PMM_PAGE Node,
					PMM_PAGING_STRUCTURE Page)
{
    assert(Page->Type == MM_PAGE_TYPE_PAGE);
    MiAvlInitializeNode(&Node->AvlNode, Page->VirtualAddr >> MM_PAGE_BITS);
    Node->PagingStructure = Page;
}

static inline VOID MiInitializeLargePageNode(PMM_LARGE_PAGE Node,
					     PMM_PAGING_STRUCTURE Page)
{
    assert(Page->Type == MM_PAGE_TYPE_LARGE_PAGE);
    MiAvlInitializeNode(&Node->AvlNode, Page->VirtualAddr >> MM_LARGE_PAGE_BITS);
    Node->PagingStructure = Page;
}

static inline VOID MiInitializePageTableNode(PMM_PAGE_TABLE Node,
					     PMM_PAGING_STRUCTURE Page)
{
    assert(Page->Type == MM_PAGE_TYPE_PAGE_TABLE);
    MiAvlInitializeNode(&Node->AvlNode, Page->VirtualAddr >> MM_LARGE_PAGE_BITS);
    MiAvlInitializeTree(&Node->MappedPages);
    Node->PagingStructure = Page;
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
