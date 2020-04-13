#pragma once

#include <nt.h>
#include <ntos.h>

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

NTSTATUS MiSplitUntyped(IN PMM_UNTYPED SrcUntyped,
			OUT PMM_UNTYPED DestUntyped1,
			OUT PMM_UNTYPED DestUntyped2);

NTSTATUS MiInsertFreeUntyped(PMM_VADDR_SPACE VaddrSpace,
			     PMM_UNTYPED Untyped);

NTSTATUS MiMapPagingStructure(PMM_PAGING_STRUCTURE Page);

#define MiAllocatePool(Var, Type)					\
    Type *Var = (Type *)ExAllocatePoolWithTag(sizeof(Type), NTOS_MM_TAG); \
    if ((Var) == NULL) { return STATUS_NTOS_OUT_OF_MEMORY; }

static inline VOID MiAvlInitializeTree(PMM_AVL_TREE Tree)
{
    Tree->BalancedRoot = NULL;
    InitializeListHead(&Tree->NodeList);
}

static inline VOID MiAvlInitializeNode(PMM_AVL_NODE Node,
				       MWORD PageNumber)
{
    Node->Parent = 0;
    Node->LeftChild = Node->RightChild = NULL;
    Node->FirstPageNumber = PageNumber;
    Node->ListEntry.Flink = Node->ListEntry.Blink = NULL;
}

static inline VOID MiInitializePageNode(PMM_PAGE Node,
					PMM_PAGING_STRUCTURE Page)
{
    assert(Page->Type == MM_PAGE_TYPE_PAGE);
    MiAvlInitializeNode(&Node->AvlNode, Page->VirtualAddr >> EX_PAGE_BITS);
    Node->PagingStructure = Page;
}

static inline VOID MiInitializeLargePageNode(PMM_LARGE_PAGE Node,
					     PMM_PAGING_STRUCTURE Page)
{
    assert(Page->Type == MM_PAGE_TYPE_LARGE_PAGE);
    MiAvlInitializeNode(&Node->AvlNode, Page->VirtualAddr >> EX_LARGE_PAGE_BITS);
    Node->PagingStructure = Page;
}

static inline VOID MiInitializePageTableNode(PMM_PAGE_TABLE Node,
					     PMM_PAGING_STRUCTURE Page)
{
    assert(Page->Type == MM_PAGE_TYPE_PAGE_TABLE);
    MiAvlInitializeNode(&Node->AvlNode, Page->VirtualAddr >> EX_LARGE_PAGE_BITS);
    MiAvlInitializeTree(&Node->MappedPages);
    Node->PagingStructure = Page;
}

static inline VOID MiInitializeVadNode(PMM_VAD Node,
				       MWORD StartPageNumber,
				       MWORD NumberOfPages)
{
    MiAvlInitializeNode(&Node->AvlNode, StartPageNumber);
    Node->NumberOfPages = NumberOfPages;
    Node->FirstLargePage = NULL;
    Node->LastLargePage = NULL;
}
