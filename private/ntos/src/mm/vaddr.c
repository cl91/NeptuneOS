/* Routines for virtual address space management */

#include "mi.h"

VOID MmInitializeVaddrSpace(IN PMM_VADDR_SPACE VaddrSpace,
			    IN MWORD VSpaceCap)
{
    VaddrSpace->VSpaceCap = VSpaceCap;
    VaddrSpace->CachedVad = NULL;
    MiAvlInitializeTree(&VaddrSpace->VadTree);
    MiAvlInitializeTree(&VaddrSpace->PageTableTree);
}

NTSTATUS MiVspaceInsertVadNode(IN PMM_VADDR_SPACE Vspace,
			       IN PMM_VAD VadNode)
{
    PMM_AVL_TREE Tree = &Vspace->VadTree;
    MWORD StartPageNum = VadNode->AvlNode.Key;
    MWORD EndPageNum = StartPageNum + VadNode->NumPages;
    PMM_VAD Parent = (PMM_VAD) MiAvlTreeFindNodeOrParent(Tree, StartPageNum);
    if (Parent != NULL && (StartPageNum >= Parent->AvlNode.Key)
	&& (EndPageNum <= Parent->AvlNode.Key + Parent->NumPages)) {
	return STATUS_NTOS_INVALID_ARGUMENT;
    }
    MiAvlTreeInsertNode(Tree, &Parent->AvlNode, &VadNode->AvlNode);
    return STATUS_SUCCESS;
}

PMM_VAD MiVspaceFindVadNode(IN PMM_VADDR_SPACE Vspace,
			    IN MWORD StartPageNum,
			    IN MWORD NumPages)
{
    PMM_AVL_TREE Tree = &Vspace->VadTree;
    MWORD EndPageNum = StartPageNum + NumPages;
    if (Vspace->CachedVad != NULL && (StartPageNum >= Vspace->CachedVad->AvlNode.Key)
	&& (EndPageNum <= Vspace->CachedVad->AvlNode.Key + Vspace->CachedVad->NumPages)) {
	/* EndPageNum <= ...: Here the equal sign is important! */
	return Vspace->CachedVad;
    }
    PMM_VAD Parent = (PMM_VAD) MiAvlTreeFindNodeOrParent(Tree, StartPageNum);
    if (Parent != NULL && (StartPageNum >= Parent->AvlNode.Key)
	&& (EndPageNum <= Parent->AvlNode.Key + Parent->NumPages)) {
	/* EndPageNum <= ...: Here the equal sign is important! */
	Vspace->CachedVad = Parent;
	return Parent;
    }
    return NULL;
}

PMM_AVL_NODE MiVspaceFindPageTableOrLargePage(IN PMM_VADDR_SPACE Vspace,
					      IN MWORD LargePageNum)
{
    PMM_AVL_TREE Tree = &Vspace->PageTableTree;
    PMM_AVL_NODE Parent = MiAvlTreeFindNodeOrParent(Tree, LargePageNum);
    if (Parent != NULL && (LargePageNum == Parent->Key)) {
	return Parent;
    }
    return NULL;
}

BOOLEAN MiPTNodeIsPageTable(PMM_AVL_NODE Node)
{
    return (Node != NULL) && (((PMM_LARGE_PAGE) Node)->PagingStructure.Type == MM_PAGE_TYPE_PAGE_TABLE);
}

BOOLEAN MiPTNodeIsLargePage(PMM_AVL_NODE Node)
{
    return (Node != NULL) && (((PMM_LARGE_PAGE) Node)->PagingStructure.Type == MM_PAGE_TYPE_LARGE_PAGE);
}

NTSTATUS MiVspaceInsertLargePage(IN PMM_VADDR_SPACE Vspace,
				 IN PMM_VAD Vad,
				 IN PMM_LARGE_PAGE LargePage)
{
    if (!LargePage->PagingStructure.Mapped) {
	return STATUS_NTOS_INVALID_ARGUMENT;
    }
    PMM_AVL_TREE Tree = &Vspace->PageTableTree;
    MWORD LargePN = LargePage->PagingStructure.VirtPageNum >> MM_LARGE_PN_SHIFT;
    PMM_AVL_NODE Parent = MiAvlTreeFindNodeOrParent(Tree, LargePN);
    if (Parent != NULL && LargePN == Parent->Key) {
	return STATUS_NTOS_INVALID_ARGUMENT;
    }
    MiAvlTreeInsertNode(Tree, Parent, &LargePage->AvlNode);
    MWORD VadStartLargePN = Vad->AvlNode.Key >> MM_LARGE_PN_SHIFT;
    MWORD VadEndLargePN = (Vad->AvlNode.Key + Vad->NumPages) >> MM_LARGE_PN_SHIFT;
    if (LargePN == VadStartLargePN) {
	Vad->FirstPageTable = &LargePage->AvlNode;
    } else if (LargePN == VadEndLargePN - 1) {
	Vad->LastPageTable = &LargePage->AvlNode;
    }
    return STATUS_SUCCESS;
}

NTSTATUS MiVspaceInsertPageTable(IN PMM_VADDR_SPACE Vspace,
				 IN PMM_VAD Vad,
				 IN PMM_PAGE_TABLE PageTable)
{
    return MiVspaceInsertLargePage(Vspace, Vad, (PMM_LARGE_PAGE) PageTable);
}

NTSTATUS MiPageTableInsertPage(IN PMM_PAGE_TABLE PageTable,
			       IN PMM_PAGE Page)
{
    if (!PageTable->PagingStructure.Mapped || !Page->PagingStructure.Mapped) {
	return STATUS_NTOS_INVALID_ARGUMENT;
    }
    PMM_AVL_TREE Tree = &PageTable->MappedPages;
    MWORD PageNum = Page->PagingStructure.VirtPageNum;
    PMM_AVL_NODE Parent = MiAvlTreeFindNodeOrParent(Tree, PageNum);
    if (Parent != NULL && PageNum == Parent->Key) {
	return STATUS_NTOS_INVALID_ARGUMENT;
    }
    MiAvlTreeInsertNode(Tree, Parent, &Page->AvlNode);
    return STATUS_SUCCESS;
}

PMM_PAGE MiPageTableFindPage(IN PMM_PAGE_TABLE PageTable,
			     IN MWORD PageNum)
{
    if (!PageTable->PagingStructure.Mapped) {
	return NULL;
    }
    PMM_AVL_TREE Tree = &PageTable->MappedPages;
    PMM_AVL_NODE Parent = MiAvlTreeFindNodeOrParent(Tree, PageNum);
    if (Parent != NULL && PageNum == Parent->Key) {
	return (PMM_PAGE) Parent;
    }
    return NULL;
}

NTSTATUS MmReserveVirtualMemoryEx(IN PMM_VADDR_SPACE Vspace,
				  IN MWORD StartPageNum,
				  IN MWORD NumPages)
{
    if (MiVspaceFindVadNode(Vspace, StartPageNum, NumPages) != NULL) {
	/* Enlarge VAD? */
	return STATUS_NTOS_INVALID_ARGUMENT;
    }

    MiAllocatePool(Vad, MM_VAD);
    MiInitializeVadNode(Vad, StartPageNum, NumPages);
    MiVspaceInsertVadNode(Vspace, Vad);
    return STATUS_SUCCESS;
}

NTSTATUS MmReserveVirtualMemory(IN MWORD StartPageNum,
				IN MWORD NumPages)
{
    return MmReserveVirtualMemoryEx(&MiNtosVaddrSpace, StartPageNum, NumPages);
}
