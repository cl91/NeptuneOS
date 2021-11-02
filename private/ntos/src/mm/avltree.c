/*
 * Balanced (AVL) Tree
 *
 * Much of the routines in this file are adapted from ReactOS source code
 * (reactos/sdk/lib/rtl/avlsupp.c)
 *
 * Reference:
 *   TAOCP Section 6.2.3 Balanced Trees
 */

#include <ntos.h>
#include <assert.h>
#include "mi.h"

/* Change below to DbgTrace(__VA_ARGS__) to enable tracing */
#define AVLTRACE(...)
#define PRINTNODE(Node)	    AVLTRACE(#Node " (%p) key is %p\n", Node, (PVOID) (Node ? Node->Key : 0))

static inline PMM_AVL_NODE MiAvlGetParent(PMM_AVL_NODE Node)
{
    MWORD ParentWord = Node->Parent;
    ParentWord &= ~((MWORD) 0x3ULL);
    return (PMM_AVL_NODE) ParentWord;
}

static inline BOOLEAN MiAvlIsRightChild(PMM_AVL_NODE Node)
{
    PMM_AVL_NODE Parent = MiAvlGetParent(Node);
    assert(Parent != NULL);
    return Parent->RightChild == Node;
}

typedef enum _AVL_NODE_BALANCE {
    LEFT_HEAVY = -1,
    BALANCED = 0,
    RIGHT_HEAVY = 1
} AVL_NODE_BALANCE;

/*
 * Get the balance factor of the given node.
 *
 * Returns -1 if node is left heavy, +1 if node is right heavy,
 * and 0 if node is balanced.
 */
static inline AVL_NODE_BALANCE MiAvlGetBalance(PMM_AVL_NODE Node)
{
    MWORD Balance = Node->Parent & 0x3ULL;
    if (Balance == 0x3) {
	return LEFT_HEAVY;
    } else if (Balance == 0x1) {
	return RIGHT_HEAVY;
    } else {
	return BALANCED;
    }
}

static inline MWORD MiAvlEncodeParent(PMM_AVL_NODE Parent,
				      AVL_NODE_BALANCE Balance)
{
    MWORD ParentWord = (MWORD) Parent;
    assert((ParentWord & 0x3) == 0);
    assert(((SCHAR) Balance <= 1) && ((SCHAR) Balance >= -1));
    if (Balance == RIGHT_HEAVY) {
	ParentWord |= 0x1;
    } else if (Balance == LEFT_HEAVY) {
	ParentWord |= 0x3;
    }
    return ParentWord;
}

static inline VOID MiAvlSetParent(PMM_AVL_NODE Node,
				  PMM_AVL_NODE NewParent)
{
    Node->Parent = MiAvlEncodeParent(NewParent, MiAvlGetBalance(Node));
}

static inline VOID MiAvlSetBalance(PMM_AVL_NODE Node,
				   AVL_NODE_BALANCE Balance)
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
 * Perform the rebalancing of a given node S, which had just
 * become unbalanced due to insertion/deletion.
 *
 * See page 463--475 of The Art of Computer Programming,
 * Volume 3, Section 6.2.3
 *
 * Returns TRUE if delete can terminate after rebalancing.
 */
static BOOLEAN MiAvlTreeRebalanceNode(PMM_AVL_TREE Tree,
				      PMM_AVL_NODE S)
{
    PMM_AVL_NODE R, P;
    AVL_NODE_BALANCE a = MiAvlGetBalance(S);

    if (a == RIGHT_HEAVY) {
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
        MiAvlSetBalance(R, BALANCED);
        MiAvlSetBalance(S, BALANCED);
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
        if (a == RIGHT_HEAVY) {
            P = R->LeftChild;
        }
        else {
            P = R->RightChild;
        }
        MiAvlTreeRotateNode(Tree, P);
        MiAvlTreeRotateNode(Tree, P);
        MiAvlSetBalance(S, BALANCED);
	MiAvlSetBalance(R, BALANCED);
        if (MiAvlGetBalance(P) == a) {
            MiAvlSetBalance(S, -a);
        } else if (MiAvlGetBalance(P) == -a) {
            MiAvlSetBalance(R, a);
        }
	MiAvlSetBalance(P, BALANCED);
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
 * Returns the node of given key if it is in the tree. Otherwise,
 * returns its parent should it be inserted.
 *
 * Note: use this to find the Parent node if you want to insert into tree.
 */
PMM_AVL_NODE MiAvlTreeFindNodeOrParent(IN PMM_AVL_TREE Tree,
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
 * Returns Node with largest key such that
 * Node->Key <= input Key
 * Returns NULL if no such node is found
 *
 * Note: don't use this to find the parent node if you want to insert into tree.
 * Use MiAvlTreeFindNodeOrParent instead.
 */
PMM_AVL_NODE MiAvlTreeFindNodeOrPrev(IN PMM_AVL_TREE Tree,
				     IN MWORD Key)
{
    PMM_AVL_NODE Parent = MiAvlTreeFindNodeOrParent(Tree, Key);
    if (Parent == NULL) {
	return NULL;
    }
    if (Parent->Key <= Key) {
	return Parent;
    }
    return MiAvlGetPrevNode(Tree, Parent);
}

/*
 * Insert tree node under Parent.
 */
VOID MiAvlTreeInsertNode(IN PMM_AVL_TREE Tree,
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
    MiAvlSetBalance(Node, BALANCED);
    PMM_AVL_NODE S = Parent;	/* S will point to node that needs rebalancing */
    PMM_AVL_NODE N = Node;
    while (S != NULL) {
	SCHAR a;
	if (S->LeftChild == N) {
	    a = LEFT_HEAVY;
	} else {
	    assert(S->RightChild == N);
	    a = RIGHT_HEAVY;
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
	    MiAvlSetBalance(S, BALANCED);
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

/*
 * Unlink the Node from the given AVL Tree, with complete disregard to balance.
 * The Node is assumed to have at most one child.
 *
 * This function should never be called by anyone except MiAvlTreeRemoveNode
 */
static VOID MiAvlTreeSimpleRemove(IN PMM_AVL_TREE Tree,
				  IN PMM_AVL_NODE Node)
{
    assert(Node->LeftChild == NULL || Node->RightChild == NULL);
    PMM_AVL_NODE Child = Node->LeftChild ? Node->LeftChild : Node->RightChild;
    PMM_AVL_NODE Parent = MiAvlGetParent(Node);
    if (Child != NULL) {
	MiAvlSetParent(Child, Parent);
    }
    if (Parent == NULL) {
	Tree->BalancedRoot = Child;
    } else {
	if (MiAvlIsRightChild(Node)) {
	    Parent->RightChild = Child;
	} else {
	    Parent->LeftChild = Child;
	}
    }
}

/*
 * Unlink the node from the AVL tree, re-balancing if necessary.
 *
 * If the given node has one or zero children, simply unlink the node, and
 * rebalance the tree if necessary.
 *
 * If the given node has two children, locate the immediate predecessor or
 * successor (depending on the balance of the given node), and unlink that
 * node instead (the actual node that we want to unlink is not removed from
 * the tree at this point). Once the new tree is rebalanced, swap the actual
 * node we want to unlink with the recently removed predecessor/successor
 * node (ie. override the LeftChild, RightChild, and Parent node pointers
 * in the recently removed predecessor/successor node with the current
 * values of these pointers at this point in the node we want to delete).
 */
VOID MiAvlTreeRemoveNode(IN PMM_AVL_TREE Tree,
			 IN PMM_AVL_NODE Node)
{
    /* Remove the node from the linear list first */
    RemoveEntryList(&Node->ListEntry);

    /* Case 1: Node has fewer than two children. Simply unlink the node. */
    PMM_AVL_NODE DeleteNode = NULL;
    if ((Node->LeftChild == NULL) || (Node->RightChild == NULL)) {
	DeleteNode = Node;
    }

    /* Case 2: Otherwise, check if one side is longer, and mark the immediate
     * predecessor/successor for deletion. */
    if ((DeleteNode == NULL) && (MiAvlGetBalance(Node) == RIGHT_HEAVY)) {
        /* Pick the successor which will be the longest side in this case */
        DeleteNode = Node->RightChild;
        while (DeleteNode->LeftChild != NULL) {
	    DeleteNode = DeleteNode->LeftChild;
	}
	assert(DeleteNode == LIST_ENTRY_TO_MM_AVL_NODE(&Node->ListEntry.Blink));
    } else if (DeleteNode == NULL) {
        /* Pick the predecessor which will be the longest side in this case */
        DeleteNode = Node->LeftChild;
        while (DeleteNode->RightChild != NULL) {
	    DeleteNode = DeleteNode->RightChild;
	}
	assert(DeleteNode == LIST_ENTRY_TO_MM_AVL_NODE(&Node->ListEntry.Flink));
    }

    /* Unlink the DeleteNode from the tree. Note that DeleteNode must have at
     * most one child. */
    PMM_AVL_NODE ParentNode = MiAvlGetParent(DeleteNode);
    AVL_NODE_BALANCE Balance = DeleteNode->LeftChild ? LEFT_HEAVY : RIGHT_HEAVY;
    MiAvlTreeSimpleRemove(Tree, DeleteNode);

    /* Rebalance the tree */
    while (ParentNode != NULL) {
        /* Check if the tree's balance increased */
        if (MiAvlGetBalance(ParentNode) == Balance) {
            /* Now the tree is balanced */
            MiAvlSetBalance(ParentNode, BALANCED);
        } else if (MiAvlGetBalance(ParentNode) == BALANCED) {
            /* The tree has now become less balanced,
	     * since it was balanced before the deletion */
            MiAvlSetBalance(ParentNode, -Balance);
            break;
	} else {
            /* The tree has become unbalanced, so a rebalance is needed */
            if (MiAvlTreeRebalanceNode(Tree, ParentNode)) {
		break;
	    }
            /* Get the new parent after the balance */
            ParentNode = MiAvlGetParent(ParentNode);
	    /* ParentNode cannot be null since the tree still needs rebalancing
	     * (otherwise MiAvlTreeRebalanceNode would have returned TRUE) */
	    assert(ParentNode != NULL);
        }

        /* Choose which balance factor to use based on which side we're on */
        Balance = MiAvlIsRightChild(ParentNode) ? RIGHT_HEAVY : LEFT_HEAVY;

        /* Iterate up the tree */
        ParentNode = MiAvlGetParent(ParentNode);
    }

    /* Check if this isn't the node we ended up deleting directly. If it is, we are done.
     * Otherwise we need to swap the DeleteNode with the Node that we actually want to
     * delete. */
    if (Node != DeleteNode) {
	DeleteNode->LeftChild = Node->LeftChild;
	DeleteNode->RightChild = Node->RightChild;
	MiAvlSetParent(DeleteNode, MiAvlGetParent(Node));
	if (MiAvlGetParent(Node) == NULL) {
	    Tree->BalancedRoot = DeleteNode;
	} else {
	    if (MiAvlIsRightChild(Node)) {
		MiAvlGetParent(Node)->RightChild = DeleteNode;
	    } else {
		MiAvlGetParent(Node)->LeftChild = DeleteNode;
	    }
	}
	Node->LeftChild = Node->RightChild = NULL;
	Node->Parent = 0;
    }
}

typedef struct _TRUNK {
    struct _TRUNK *Prev;
    char *Str;
} TRUNK, *PTRUNK;

// Helper function to print branches of the binary tree
static void MiAvlTreeShowTrunks(PTRUNK p)
{
    if (p == NULL)
        return;

    MiAvlTreeShowTrunks(p->Prev);

    if (p->Str != NULL) {
	DbgPrint("%s", p->Str);
    }
}

// Recursive function to print binary tree
// It uses inorder traversal
static void MiAvlTreePrintTree(PMM_AVL_NODE Root,
			       PTRUNK Prev,
			       BOOLEAN IsLeft)
{
    if (Root == NULL)
        return;

    char *PrevStr = "    ";
    TRUNK Trunk = { .Prev = Prev,
		    .Str = PrevStr };

    MiAvlTreePrintTree(Root->LeftChild, &Trunk, TRUE);

    if (!Prev) {
        Trunk.Str = "---";
    } else if (IsLeft) {
        Trunk.Str = ".---";
        PrevStr = "   |";
    } else {
        Trunk.Str = "`---";
        Prev->Str = PrevStr;
    }

    MiAvlTreeShowTrunks(&Trunk);
    DbgPrint("%05zx\n", Root->Key >> PAGE_LOG2SIZE);

    if (Prev)
        Prev->Str = PrevStr;
    Trunk.Str = "   |";

    MiAvlTreePrintTree(Root->RightChild, &Trunk, FALSE);
}

VOID MmAvlDumpTree(PMM_AVL_TREE tree)
{
    MiAvlTreePrintTree(tree->BalancedRoot, NULL, TRUE);
}

VOID MmAvlDumpTreeLinear(PMM_AVL_TREE tree)
{
    LoopOverList(Node, &tree->NodeList, MM_AVL_NODE, ListEntry) {
	DbgPrint("%p ", (PVOID) Node->Key);
    }
}

VOID MmAvlVisitTreeLinear(PMM_AVL_TREE Tree, PMM_AVL_TREE_VISITOR Visitor)
{
    assert(Tree != NULL);
    assert(Visitor != NULL);
    LoopOverList(Node, &Tree->NodeList, MM_AVL_NODE, ListEntry) {
	Visitor(Node);
    }
}
