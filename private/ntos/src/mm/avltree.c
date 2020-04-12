/*
 * Balanced (AVL) Tree
 *
 * Reference:
 *   TAOCP Section 6.2.3 Balanced Trees
 *
 */

#include <ntos.h>
#include <assert.h>

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
 * Returns Node with largest FirstPageNumber such that
 * Node->FirstPageNumber <= input FirstPageNumber
 * Returns NULL if no such node is found
 */
static PMM_AVL_NODE
MiAvlTreeFindNode(IN PMM_AVL_TREE Tree,
		  IN MWORD FirstPageNumber)
{
    PMM_AVL_NODE Node = Tree->BalancedRoot;
    if (Node == NULL) {
	return NULL;
    }
    PMM_AVL_NODE PrevNode = Node;
    while (Node != NULL) {
	if (FirstPageNumber == Node->FirstPageNumber) {
	    return Node;
	} else if (FirstPageNumber < Node->FirstPageNumber) {
	    Node = Node->LeftChild;
	    PrevNode = Node;
	} else {
	    Node = Node->RightChild;
	}
    }
    return PrevNode;
}

/*
 * Insert tree node between PrevNode and PrevNode->Flink,
 * where PrevNode is the largest node such that
 * PrevNode->FirstPageNumber <= Node->FirstPageNumber
 */
static VOID
MiAvlTreeInsertNode(IN PMM_AVL_TREE Tree,
		    IN PMM_AVL_NODE PrevNode,
		    IN PMM_AVL_NODE Node)
{
    Node->LeftChild = NULL;
    Node->RightChild = NULL;

    if (Tree->BalancedRoot == NULL) { /* Tree is empty */
	Tree->BalancedRoot = Node;
	Node->Parent = 0;
	assert(IsListEmpty(&Tree->NodeList));
	InsertHeadList(&Tree->NodeList, &Node->ListEntry);
	return;
    }

    PMM_AVL_NODE Parent;
    SCHAR a;			/* a == -1 means left insertion, 1 right insertion */
    if (PrevNode == NULL) {
	/* Insert before the left-most node (first node in linear order) */
	Parent = CONTAINING_RECORD(Tree->NodeList.Flink, MM_AVL_NODE, ListEntry);
	assert(Parent != NULL);
	assert(Parent->LeftChild == NULL);
	a = -1;
    } else if (PrevNode->RightChild == NULL) {
	/* Right insertion */
	Parent = PrevNode;
	a = 1;
    } else {
	/* Insert as the left child of PrevNode->Flink */
	assert(PrevNode->ListEntry.Flink != &Tree->NodeList);
	Parent = CONTAINING_RECORD(PrevNode->ListEntry.Flink, MM_AVL_NODE, ListEntry);
	assert(Parent->LeftChild == NULL);
	a = -1;
    }

    MiAvlSetParent(Node, Parent);
    if (a == -1) {
	Parent->LeftChild = Node;
	InsertTailList(&Parent->ListEntry, &Node->ListEntry);
    } else {
	Parent->RightChild = Node;
	InsertHeadList(&Parent->ListEntry, &Node->ListEntry);
    }

    /* Adjust balance and perform necessary rebalancing */
    MiAvlSetBalance(Node, 0);
    PMM_AVL_NODE S = Parent;	/* S points to node that needs rebalancing */
    while (S != NULL) {
	SCHAR b = MiAvlGetBalance(S);
	if (b == 0) {
	    /* Tree just became unbalanced, but no rebalancing needed yet */
	    MiAvlSetBalance(S, a);
	    /* Continue going up the tree */
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

NTSTATUS MmVadTreeInsertNode(IN PMM_VADDR_SPACE Vspace,
			     IN PMM_VAD VadNode)
{
    PMM_AVL_TREE Tree = &Vspace->VadTree;
    MWORD NodeStartPN = VadNode->AvlNode.FirstPageNumber;
    PMM_VAD PrevNode = (PMM_VAD) MiAvlTreeFindNode(Tree, NodeStartPN);
    if (PrevNode != NULL && NodeStartPN < PrevNode->AvlNode.FirstPageNumber + PrevNode->NumberOfPages) {
	return STATUS_NTOS_INVALID_ARGUMENT;
    }
    MiAvlTreeInsertNode(Tree, &PrevNode->AvlNode, &VadNode->AvlNode);
    return STATUS_SUCCESS;
}
