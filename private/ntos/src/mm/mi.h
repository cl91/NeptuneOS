#pragma once

#include <nt.h>
#include <ntos.h>

/* Information needed to initialize the Memory Management subcomponent,
 * including the Executive Pool */
typedef struct _MM_INIT_INFO {
    MWORD InitVSpaceCap;
    MWORD InitUntypedCap;
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
VOID MiInitializeUntyped(IN PMM_UNTYPED Untyped,
			 IN PMM_UNTYPED Parent,
			 IN PMM_VADDR_SPACE VaddrSpace,
			 IN MWORD Cap,
			 IN LONG Log2Size);
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

/* arch/init.c */
NTSTATUS MiInitMapInitialHeap(IN PMM_INIT_INFO InitInfo,
			      OUT LONG *PoolPages,
			      OUT MWORD *FreeCapStart);
NTSTATUS MiInitRecordUntypedAndPages(IN PMM_INIT_INFO InitInfo,
				     IN PMM_VADDR_SPACE VaddrSpace,
				     IN PMM_VAD ExPoolVad);
NTSTATUS MiInitRecordUserImagePaging(IN PMM_INIT_INFO InitInfo,
				     IN PMM_VADDR_SPACE VaddrSpace,
				     IN PMM_VAD UserImageVad);

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
NTSTATUS MiRequestIoUntyped(IN PMM_IO_UNTYPED RootIoUntyped,
			    IN MWORD PhyPageNum,
			    OUT PMM_IO_UNTYPED *IoUntyped);

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
PMM_PAGE MiPageTableFindPage(IN PMM_PAGE_TABLE PageTable,
			     IN MWORD PageNum);
NTSTATUS MiVspaceInsertRootIoUntyped(IN PMM_VADDR_SPACE VaddrSpace,
				     IN PMM_IO_UNTYPED RootIoUntyped);
PMM_IO_UNTYPED MiVspaceFindRootIoUntyped(IN PMM_VADDR_SPACE VaddrSpace,
					 IN MWORD PhyPageNum);

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
