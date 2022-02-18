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

/* Change this to 0 to enable debug tracing */
#if 1
#undef DbgTrace
#define DbgTrace(...)
#define DbgPrint(...)
#else
#include <dbgtrace.h>
#endif

#define AVLTRACE(...)	DbgTrace(__VA_ARGS__)
#define PRINTNODE(Node)							\
    if (Node) {								\
	AVLTRACE(#Node " (%p) key is %p\n", Node, (PVOID)Node->Key);	\
    } else {								\
	AVLTRACE(#Node " is (nil)\n");					\
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
    assert(R != NULL);
    assert(a != BALANCED);

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
    assert(MiAvlGetBalance(S) == a);
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
 * Returns Node with largest key such that Node->Key <= input Key.
 *
 * In other words, if the tree has a node with the given key, this routine
 * returns that node. Otherwise, pretend that a node with the given key is
 * inserted into the tree, and this routine returns its previous node.
 *
 * Returns NULL if no such node is found.
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
    return MiAvlGetPrevNode(Parent);
}

/*
 * Returns the node of given key if it is in the tree. Otherwise,
 * returns NULL.
 */
PMM_AVL_NODE MmAvlTreeFindNode(IN PMM_AVL_TREE Tree,
			       IN MWORD Key)
{
    assert(Tree != NULL);
    PMM_AVL_NODE Node = Tree->BalancedRoot;
    if (Node == NULL) {
	return NULL;
    }
    while (Node != NULL) {
	if (Key == Node->Key) {
	    return Node;
	}
	if (Key < Node->Key) {
	    Node = Node->LeftChild;
	} else {
	    Node = Node->RightChild;
	}
    }
    return NULL;
}

/*
 * Insert the node as the last element of the tree, overriding its
 * key with the key of the original last element plus the given
 * increment. The increment cannot be zero. The increment cannot
 * be so large that the new key overflows. If the tree is empty,
 * the node will have the given increment as the key.
 */
VOID MmAvlTreeAppendNode(IN PMM_AVL_TREE Tree,
			 IN OUT PMM_AVL_NODE Node,
			 IN MWORD Increment)
{
    assert(Tree != NULL);
    assert(Node != NULL);
    assert(Increment != 0);
    if (MiAvlTreeIsEmpty(Tree)) {
	Node->Key = Increment;
	MiAvlTreeInsertNode(Tree, NULL, Node);
    } else {
	/* Find the last node in the tree */
	PMM_AVL_NODE Last = MiAvlGetLastNode(Tree);
	assert(Last != NULL);
	Node->Key = Last->Key + Increment;
	if (Node->Key < Last->Key) {
	    /* Integer overflow. We simply return in this case. */
	    return;
	}
	MiAvlTreeInsertNode(Tree, Last, Node);
    }
}

/*
 * Insert tree node under Parent.
 */
VOID MiAvlTreeInsertNode(IN PMM_AVL_TREE Tree,
			 IN PMM_AVL_NODE Parent,
			 IN PMM_AVL_NODE Node)
{
    assert(Tree != NULL);
    assert(Node != NULL);
    assert(Parent == NULL || Parent->LeftChild == NULL || Parent->RightChild == NULL);
    DbgTrace("Inserting node %p (key %p) parent %p (key %p) to tree %p\n",
	     Node, (PVOID)Node->Key, Parent,
	     Parent ? (PVOID)Parent->Key : NULL, Tree);
    Node->LeftChild = NULL;
    Node->RightChild = NULL;

    /* If tree is empty, insert as BalancedRoot */
    if (Tree->BalancedRoot == NULL || Parent == NULL) {
	Tree->BalancedRoot = Node;
	Node->Parent = 0;
	return;
    }

    /* Insert as child of Parent */
    if (Node->Key == Parent->Key) {
	return;
    } else if (Node->Key < Parent->Key) {
	assert(Parent->LeftChild == NULL);
	Parent->LeftChild = Node;
    } else {
	assert(Parent->RightChild == NULL);
	Parent->RightChild = Node;
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
	if (b == BALANCED) {
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
 * Simply unlink the Node from the given AVL Tree, without adjusting balance.
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
    Node->Parent = 0;
    Node->LeftChild = NULL;
    Node->RightChild = NULL;
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
    DbgTrace("Removing node %p (key %p) from tree %p\n",
	     Node, (PVOID)Node->Key, Tree);
    MmAvlDumpTree(Tree);

    PMM_AVL_NODE DeleteNode = NULL;
    if ((Node->LeftChild == NULL) || (Node->RightChild == NULL)) {
	/* Case 1: Node has fewer than two children. Simply unlink the node. */
	DeleteNode = Node;
    } else {
	/* Case 2: Otherwise, check if one side is longer, and mark the immediate
	 * predecessor/successor for deletion. */
	if (MiAvlGetBalance(Node) == RIGHT_HEAVY) {
	    /* Pick the successor which will be the longest side in this case */
	    DeleteNode = MiAvlGetNextNode(Node);
	} else {
	    /* Pick the predecessor which will be the longest side in this case */
	    DeleteNode = MiAvlGetNextNode(Node);
	}
    }

    /* Unlink the DeleteNode from the tree. Note that DeleteNode must have at
     * most one child. */
    assert(DeleteNode->LeftChild == NULL || DeleteNode->RightChild == NULL);
    PMM_AVL_NODE ParentNode = MiAvlGetParent(DeleteNode);
    AVL_NODE_BALANCE Balance;
    if (ParentNode != NULL) {
	Balance = MiAvlIsLeftChild(DeleteNode) ? LEFT_HEAVY : RIGHT_HEAVY;
    }
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
	if (MiAvlGetParent(ParentNode) != NULL) {
	    Balance = MiAvlIsRightChild(ParentNode) ? RIGHT_HEAVY : LEFT_HEAVY;
	}

        /* Iterate up the tree */
        ParentNode = MiAvlGetParent(ParentNode);
    }

    /* Check if this isn't the node we ended up deleting directly. If it is, we are done.
     * Otherwise we need to swap the DeleteNode with the Node that we actually want to
     * delete. */
    if (Node != DeleteNode) {
	DeleteNode->LeftChild = Node->LeftChild;
	DeleteNode->RightChild = Node->RightChild;
	if (Node->LeftChild != NULL) {
	    MiAvlSetParent(Node->LeftChild, DeleteNode);
	}
	if (Node->RightChild != NULL) {
	    MiAvlSetParent(Node->RightChild, DeleteNode);
	}
	DeleteNode->Parent = Node->Parent;
	if (MiAvlGetParent(Node) == NULL) {
	    Tree->BalancedRoot = DeleteNode;
	} else if (MiAvlIsRightChild(Node)) {
	    MiAvlGetParent(Node)->RightChild = DeleteNode;
	} else {
	    assert(MiAvlIsLeftChild(Node));
	    MiAvlGetParent(Node)->LeftChild = DeleteNode;
	}
	Node->LeftChild = Node->RightChild = NULL;
	Node->Parent = 0;
    }
    DbgTrace("After deletion\n");
    MmAvlDumpTree(Tree);
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
    CHAR c;
    if (MiAvlGetBalance(Root) == BALANCED) {
	c = '|';
    } else if (MiAvlGetBalance(Root) == LEFT_HEAVY) {
	c = '-';
    } else if (MiAvlGetBalance(Root) == RIGHT_HEAVY) {
	c = '+';
    }
    DbgPrint("%05zx%c\n", Root->Key >> PAGE_LOG2SIZE, c);

    if (Prev)
        Prev->Str = PrevStr;
    Trunk.Str = "   |";

    MiAvlTreePrintTree(Root->RightChild, &Trunk, FALSE);
}

VOID MmAvlDumpTree(PMM_AVL_TREE tree)
{
    MiAvlTreePrintTree(tree->BalancedRoot, NULL, TRUE);
}

static VOID MiAvlVisitTree(IN PMM_AVL_NODE Node)
{
    DbgPrint("%p ", (PVOID) Node->Key);
}

VOID MmAvlVisitTreeLinear(PMM_AVL_TREE Tree,
			  PMM_AVL_TREE_VISITOR Visitor)
{
    assert(Tree != NULL);
    assert(Visitor != NULL);
    PMM_AVL_NODE Node = MiAvlGetFirstNode(Tree);
    while (Node != NULL) {
	Visitor(Node);
	Node = MiAvlGetNextNode(Node);
    }
}

VOID MmAvlDumpTreeLinear(PMM_AVL_TREE Tree)
{
    MmAvlVisitTreeLinear(Tree, MiAvlVisitTree);
}
