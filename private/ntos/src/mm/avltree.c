/*
 * Balanced (AVL) Tree
 *
 * Reference:
 *   TAOCP Section 6.2.3 Balanced Trees
 *
 */

#include <ntos.h>
#include <assert.h>
#include "mi.h"

static inline PMM_AVL_NODE
MiAvlGetParent(PMM_AVL_NODE Node)
{
    MWORD ParentWord = Node->Parent;
    ParentWord &= ~((MWORD) 0x3);
    return (PMM_AVL_NODE) ParentWord;
}

static inline SCHAR
MiAvlGetBalance(PMM_AVL_NODE Node)
{
    MWORD Balance = Node->Parent & 0x3;
    if (Balance == 0x3) {
	return -1;
    } else if (Balance == 0x1) {
	return 1;
    } else {
	return 0;
    }
}

static inline MWORD
MiAvlEncodeParent(PMM_AVL_NODE Parent,
		  SCHAR Balance)
{
    MWORD ParentWord = (MWORD) Parent;
    assert((ParentWord & 0x3) == 0);
    assert((Balance <= 1) && (Balance >= -1));
    if (Balance == 1) {
	ParentWord |= 0x1;
    } else if (Balance == -1) {
	ParentWord |= 0x3;
    }
    return ParentWord;
}

static inline VOID
MiAvlSetParent(PMM_AVL_NODE Node,
	       PMM_AVL_NODE NewParent)
{
    Node->Parent = MiAvlEncodeParent(NewParent, MiAvlGetBalance(Node));
}

static inline VOID
MiAvlSetBalance(PMM_AVL_NODE Node,
		SCHAR Balance)
{
    Node->Parent = MiAvlEncodeParent(MiAvlGetParent(Node), Balance);
}

/*
 * Rotate node such that node becomes the parent of its parent
 *
 *   T1, T2 and T3 are subtrees of the tree rooted with y (on
 *   the left side) or x (on the right side)
 *
 *           y                               x
 *          / \      Right Rotation         / \
 *  (Node) x   T3    - - - - - - - >       T1  y (Node)
 *        / \        < - - - - - - -          / \
 *       T1  T2      Left Rotation           T2  T3
 *
 *   After rotation Node becomes the new parent of its old parent
 *
 */
static VOID MiAvlTreeRotateNode(PMM_AVL_TREE Tree,
				PMM_AVL_NODE Node)
{
    PMM_AVL_NODE Parent = MiAvlGetParent(Node);
    if (Parent == NULL) {	/* Do nothing if trying to rotate root */
	return;
    }

    PMM_AVL_NODE GrandParent = MiAvlGetParent(Parent);
    BOOLEAN GrandParentIsRoot = (GrandParent == NULL);

    if (Parent->LeftChild == Node) {
	/*
                  P           N
                 / \   =>    / \
                N   z       x   P
               / \             / \
              x   y           y   z
	*/
	Parent->LeftChild = Node->RightChild;
	Node->RightChild = Parent;
	if (Parent->LeftChild != NULL) {
            MiAvlSetParent(Parent->LeftChild, Parent);
	}
    } else {
	assert(Parent->RightChild == Node);
	/*
                P               N
               / \     =>      / \
              x   N           P   z
                 / \         / \
                y   z       x   y
	*/
        Parent->RightChild = Node->LeftChild;
        Node->LeftChild = Parent;
        if (Parent->RightChild != NULL) {
            MiAvlSetParent(Parent->RightChild, Parent);
        }
    }

    /*
         P            N
         |     =>     |
         N            P
    */
    MiAvlSetParent(Parent, Node);

    /*
         G            G
         |     =>     |
         P            N
    */
    MiAvlSetParent(Node, GrandParent);
    if (GrandParentIsRoot) {
	Tree->BalancedRoot = Node;
    } else if (GrandParent->LeftChild == Parent) {
	GrandParent->LeftChild = Node;
    } else {
        assert(GrandParent->RightChild == Parent);
        GrandParent->RightChild = Node;
    }
}

/*
 * Performs the rebalancing of a given node S, which had just
 * become unbalanced due to insertion/deletion
 * See page 463--475 of TAOCP Volume 3, Section 6.2.3
 * Returns TRUE if delete can terminate after rebalancing.
 */
static BOOLEAN
MiAvlTreeRebalanceNode(PMM_AVL_TREE Tree,
		       PMM_AVL_NODE S)
{
    PMM_AVL_NODE R, P;
    SCHAR a = MiAvlGetBalance(S);

    if (a == +1) {
        R = S->RightChild;
    } else {
        R = S->LeftChild;
    }

    /*
      Case 1: Single Rotation. (Step A8, A10)
                |                   |
                S++                 R
               / \                 / \
             [h]  R+     ==>      S  [h+1]
                 / \             / \
               [h] [h+1]       [h] [h]
    */
    if (MiAvlGetBalance(R) == a) {
        MiAvlTreeRotateNode(Tree, R);
        MiAvlSetBalance(R, 0);
        MiAvlSetBalance(S, 0);
        return FALSE;
    }

    /*
      Case 2: Double Rotation (Step A9, A10)
              |                   |
              S++                 P
             / \                 / \
            /   \               /   \
           /     \             /     \
         [h]      R-   ==>    S-      R
                 / \         / \     / \
                P+ [h]     [h][h-1][h] [h]
               / \
           [h-1] [h]

              |                   |
              S++                 P
             / \                 / \
            /   \               /   \
           /     \             /     \
         [h]      R-   ==>    S       R+
                 / \         / \     / \
                P- [h]     [h] [h][h-1][h]
               / \
             [h] [h-1]
    */
    if (MiAvlGetBalance(R) == -a) {
        if (a == 1) {
            P = R->LeftChild;
        }
        else {
            P = R->RightChild;
        }
        MiAvlTreeRotateNode(Tree, P);
        MiAvlTreeRotateNode(Tree, P);
        MiAvlSetBalance(S, 0);
	MiAvlSetBalance(R, 0);
        if (MiAvlGetBalance(P) == a) {
            MiAvlSetBalance(S, -a);
        } else if (MiAvlGetBalance(P) == -a) {
            MiAvlSetBalance(R, a);
        }
	MiAvlSetBalance(P, 0);
        return FALSE;
    }

    /*
      Case 3 (Delete only): Single Rotation (pp. 473--475)
              |                   |
              S++                 R-
             / \                 / \
           (h)  R      ==>      S+ (h+1)
               / \             / \
            (h+1)(h+1)       (h) (h+1)
    */
    MiAvlTreeRotateNode(Tree, R);
    MiAvlSetBalance(R, -a);
    return TRUE;
}

/*
 * Returns Node with largest key such that
 * Node->Key <= input Key
 * Returns NULL if no such node is found
 */
static PMM_AVL_NODE
MiAvlTreeFindNodeOrParent(IN PMM_AVL_TREE Tree,
			  IN MWORD Key)
{
    PMM_AVL_NODE Node = Tree->BalancedRoot;
    if (Node == NULL) {
	return NULL;
    }
    PMM_AVL_NODE Parent = Node;
    while (Node != NULL) {
	if (Key == Node->Key) {
	    return Node;
	}
	Parent = Node;
	if (Key < Node->Key) {
	    Node = Node->LeftChild;
	} else {
	    Node = Node->RightChild;
	}
    }
    return Parent;
}

/*
 * Insert tree node under Parent.
 */
static VOID
MiAvlTreeInsertNode(IN PMM_AVL_TREE Tree,
		    IN PMM_AVL_NODE Parent,
		    IN PMM_AVL_NODE Node)
{
    Node->LeftChild = NULL;
    Node->RightChild = NULL;

    /* If tree is empty, insert as BalancedRoot */
    if (Tree->BalancedRoot == NULL || Parent == NULL) {
	Tree->BalancedRoot = Node;
	Node->Parent = 0;
	assert(IsListEmpty(&Tree->NodeList));
	InsertHeadList(&Tree->NodeList, &Node->ListEntry);
	return;
    }

    /* Insert as child of Parent */
    if (Node->Key == Parent->Key) {
	return;
    } else if (Node->Key < Parent->Key) {
	assert(Parent->LeftChild == NULL);
	Parent->LeftChild = Node;
	InsertTailList(&Parent->ListEntry, &Node->ListEntry);
    } else {
	assert(Parent->RightChild == NULL);
	Parent->RightChild = Node;
	InsertHeadList(&Parent->ListEntry, &Node->ListEntry);
    }
    MiAvlSetParent(Node, Parent);

    /* Adjust balance and perform necessary rebalancing */
    MiAvlSetBalance(Node, 0);
    PMM_AVL_NODE S = Parent;	/* S will point to node that needs rebalancing */
    PMM_AVL_NODE N = Node;
    while (S != NULL) {
	SCHAR a;
	if (S->LeftChild == N) {
	    a = -1;
	} else {
	    assert(S->RightChild == N);
	    a = 1;
	}
	SCHAR b = MiAvlGetBalance(S);
	if (b == 0) {
	    /* Tree just became unbalanced, but no rebalancing needed yet */
	    MiAvlSetBalance(S, a);
	    /* Continue going up the tree */
	    N = S;
	    S = MiAvlGetParent(S);
	} else if (b == -a) {
	    /* Tree just became more balanced */
	    MiAvlSetBalance(S, 0);
	    /* No need to continue */
	    break;
	} else {		/* b == a */
	    /* Tree needs rebalancing */
	    MiAvlTreeRebalanceNode(Tree, S);
	    /* No need to continue */
	    break;
	}
    }
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
    if (Vspace->Caches.Vad != NULL && (StartPageNum >= Vspace->Caches.Vad->AvlNode.Key)
	&& (EndPageNum <= Vspace->Caches.Vad->AvlNode.Key + Vspace->Caches.Vad->NumPages)) {
	/* EndPageNum <= ...: Here the equal sign is important! */
	return Vspace->Caches.Vad;
    }
    PMM_VAD Parent = (PMM_VAD) MiAvlTreeFindNodeOrParent(Tree, StartPageNum);
    if (Parent != NULL && (StartPageNum >= Parent->AvlNode.Key)
	&& (EndPageNum <= Parent->AvlNode.Key + Parent->NumPages)) {
	/* EndPageNum <= ...: Here the equal sign is important! */
	Vspace->Caches.Vad = Parent;
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
    return (Node != NULL) && (((PMM_LARGE_PAGE) Node)->PagingStructure->Type == MM_PAGE_TYPE_PAGE_TABLE);
}

BOOLEAN MiPTNodeIsLargePage(PMM_AVL_NODE Node)
{
    return (Node != NULL) && (((PMM_LARGE_PAGE) Node)->PagingStructure->Type == MM_PAGE_TYPE_LARGE_PAGE);
}

NTSTATUS MiVspaceInsertLargePage(IN PMM_VADDR_SPACE Vspace,
				 IN PMM_VAD Vad,
				 IN PMM_LARGE_PAGE LargePage)
{
    if (!LargePage->PagingStructure->Mapped) {
	return STATUS_NTOS_INVALID_ARGUMENT;
    }
    PMM_AVL_TREE Tree = &Vspace->PageTableTree;
    MWORD LargePN = LargePage->PagingStructure->VirtualAddr >> MM_LARGE_PAGE_BITS;
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
    if (!PageTable->PagingStructure->Mapped || !Page->PagingStructure->Mapped) {
	return STATUS_NTOS_INVALID_ARGUMENT;
    }
    PMM_AVL_TREE Tree = &PageTable->MappedPages;
    MWORD PageNum = Page->PagingStructure->VirtualAddr >> MM_PAGE_BITS;
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
    if (!PageTable->PagingStructure->Mapped) {
	return NULL;
    }
    PMM_AVL_TREE Tree = &PageTable->MappedPages;
    PMM_AVL_NODE Parent = MiAvlTreeFindNodeOrParent(Tree, PageNum);
    if (Parent != NULL && PageNum == Parent->Key) {
	return (PMM_PAGE) Parent;
    }
    return NULL;
}

NTSTATUS MiVspaceInsertRootIoUntyped(IN PMM_VADDR_SPACE VaddrSpace,
				     IN PMM_IO_UNTYPED RootIoUntyped)
{
    assert(RootIoUntyped->Untyped.Log2Size >= MM_PAGE_BITS);
    MWORD StartPageNum = RootIoUntyped->AvlNode.Key;
    MWORD EndPageNum = StartPageNum + (1 << (RootIoUntyped->Untyped.Log2Size - MM_PAGE_BITS));
    PMM_AVL_TREE Tree = &VaddrSpace->RootIoUntypedTree;
    PMM_IO_UNTYPED Parent = (PMM_IO_UNTYPED) MiAvlTreeFindNodeOrParent(Tree, StartPageNum);
    if (Parent != NULL && (StartPageNum >= Parent->AvlNode.Key)
	&& (EndPageNum <= Parent->AvlNode.Key + (1 << (Parent->Untyped.Log2Size - MM_PAGE_BITS)))) {
	/* EndPageNum <= ...: Here the equal sign is important! */
	return STATUS_NTOS_INVALID_ARGUMENT;
    }
    MiAvlTreeInsertNode(Tree, &Parent->AvlNode, &RootIoUntyped->AvlNode);
    return STATUS_SUCCESS;
}

PMM_IO_UNTYPED MiVspaceFindRootIoUntyped(IN PMM_VADDR_SPACE VaddrSpace,
					 IN MWORD PhyPageNum)
{
    PMM_AVL_TREE Tree = &VaddrSpace->RootIoUntypedTree;
    if (VaddrSpace->Caches.RootIoUntyped != NULL && (PhyPageNum >= VaddrSpace->Caches.RootIoUntyped->AvlNode.Key)
	&& (PhyPageNum < VaddrSpace->Caches.RootIoUntyped->AvlNode.Key +
	    (1 << (VaddrSpace->Caches.RootIoUntyped->Untyped.Log2Size - MM_PAGE_BITS)))) {
	return VaddrSpace->Caches.RootIoUntyped;
    }
    PMM_IO_UNTYPED Parent = (PMM_IO_UNTYPED) MiAvlTreeFindNodeOrParent(Tree, PhyPageNum);
    if (Parent != NULL && (PhyPageNum >= Parent->AvlNode.Key)
	&& (PhyPageNum < Parent->AvlNode.Key + (1 << (Parent->Untyped.Log2Size - MM_PAGE_BITS)))) {
	VaddrSpace->Caches.RootIoUntyped = Parent;
	return Parent;
    }
    return NULL;
}
