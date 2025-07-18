/*
 * Balanced (AVL) Tree
 *
 * Much of the routines in this file are adapted from ReactOS source code
 * (reactos/sdk/lib/rtl/avlsupp.c)
 *
 * Reference:
 *   TAOCP Section 6.2.3 Balanced Trees
 */

/* Comment this out to enable debug tracing on debug build */
#ifndef NDEBUG
#define NDEBUG
#endif

#include <avltree.h>

#define PRINTNODE(Node)							\
    if (Node) {								\
	DbgTrace(#Node " (%p) key is %p\n", Node, (PVOID)Node->Key);	\
    } else {								\
	DbgTrace(#Node " is (nil)\n");					\
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
static inline AVL_NODE_BALANCE AvlpGetBalance(PAVL_NODE Node)
{
    ULONG64 Balance = Node->Parent & 0x3ULL;
    if (Balance == 0x3) {
	return LEFT_HEAVY;
    } else if (Balance == 0x1) {
	return RIGHT_HEAVY;
    } else {
	return BALANCED;
    }
}

static inline ULONG64 AvlpEncodeParent(PAVL_NODE Parent,
				       AVL_NODE_BALANCE Balance)
{
    ULONG64 ParentWord = (ULONG64) Parent;
    assert((ParentWord & 0x3) == 0);
    assert(((SCHAR) Balance <= 1) && ((SCHAR) Balance >= -1));
    if (Balance == RIGHT_HEAVY) {
	ParentWord |= 0x1;
    } else if (Balance == LEFT_HEAVY) {
	ParentWord |= 0x3;
    }
    return ParentWord;
}

static inline VOID AvlpSetParent(PAVL_NODE Node,
				 PAVL_NODE NewParent)
{
    Node->Parent = AvlpEncodeParent(NewParent, AvlpGetBalance(Node));
}

static inline VOID AvlpSetBalance(PAVL_NODE Node,
				  AVL_NODE_BALANCE Balance)
{
    Node->Parent = AvlpEncodeParent(AvlGetParent(Node), Balance);
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
static VOID AvlpTreeRotateNode(PAVL_TREE Tree,
			       PAVL_NODE Node)
{
    PAVL_NODE Parent = AvlGetParent(Node);
    if (Parent == NULL) {	/* Do nothing if trying to rotate root */
	return;
    }

    PAVL_NODE GrandParent = AvlGetParent(Parent);
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
            AvlpSetParent(Parent->LeftChild, Parent);
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
            AvlpSetParent(Parent->RightChild, Parent);
        }
    }

    /*
         P            N
         |     =>     |
         N            P
    */
    AvlpSetParent(Parent, Node);

    /*
         G            G
         |     =>     |
         P            N
    */
    AvlpSetParent(Node, GrandParent);
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
static BOOLEAN AvlpTreeRebalanceNode(PAVL_TREE Tree,
				     PAVL_NODE S)
{
    PAVL_NODE R, P;
    AVL_NODE_BALANCE a = AvlpGetBalance(S);

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
    if (AvlpGetBalance(R) == a) {
        AvlpTreeRotateNode(Tree, R);
        AvlpSetBalance(R, BALANCED);
        AvlpSetBalance(S, BALANCED);
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
    if (AvlpGetBalance(R) == -a) {
        if (a == RIGHT_HEAVY) {
            P = R->LeftChild;
        }
        else {
            P = R->RightChild;
        }
        AvlpTreeRotateNode(Tree, P);
        AvlpTreeRotateNode(Tree, P);
        AvlpSetBalance(S, BALANCED);
	AvlpSetBalance(R, BALANCED);
        if (AvlpGetBalance(P) == a) {
            AvlpSetBalance(S, -a);
        } else if (AvlpGetBalance(P) == -a) {
            AvlpSetBalance(R, a);
        }
	AvlpSetBalance(P, BALANCED);
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
    AvlpTreeRotateNode(Tree, R);
    AvlpSetBalance(R, -a);
    assert(AvlpGetBalance(S) == a);
    return TRUE;
}

/*
 * Returns the node of given key if it is in the tree. Otherwise,
 * returns its parent should it be inserted.
 *
 * Note: use this to find the Parent node if you want to insert into tree.
 */
PAVL_NODE AvlTreeFindNodeOrParent(IN PAVL_TREE Tree,
				  IN ULONG64 Key)
{
    PAVL_NODE Node = Tree->BalancedRoot;
    if (Node == NULL) {
	return NULL;
    }
    PAVL_NODE Parent = Node;
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
 * Use AvlTreeFindNodeOrParent instead.
 */
PAVL_NODE AvlTreeFindNodeOrPrevEx(IN PAVL_TREE Tree,
				  IN ULONG64 Key,
				  OUT OPTIONAL PAVL_NODE *pParent)
{
    PAVL_NODE Parent = AvlTreeFindNodeOrParent(Tree, Key);
    if (Parent == NULL) {
	return NULL;
    }
    if (pParent) {
	*pParent = Parent;
    }
    if (Parent->Key <= Key) {
	return Parent;
    }
    return AvlGetPrevNode(Parent);
}

/*
 * Returns Node with the smallest key such that Node->Key >= input Key.
 *
 * In other words, if the tree has a node with the given key, this routine
 * returns that node. Otherwise, pretend that a node with the given key is
 * inserted into the tree, and this routine returns its next node.
 *
 * Returns NULL if no such node is found.
 *
 * Note: don't use this to find the parent node if you want to insert into tree.
 * Use AvlTreeFindNodeOrParent instead.
 */
PAVL_NODE AvlTreeFindNodeOrNextEx(IN PAVL_TREE Tree,
				  IN ULONG64 Key,
				  OUT OPTIONAL PAVL_NODE *pParent)
{
    PAVL_NODE Parent = AvlTreeFindNodeOrParent(Tree, Key);
    if (Parent == NULL) {
	return NULL;
    }
    if (pParent) {
	*pParent = Parent;
    }
    if (Parent->Key >= Key) {
	return Parent;
    }
    return AvlGetNextNode(Parent);
}

/*
 * Returns the node of given key if it is in the tree. Otherwise,
 * returns NULL.
 */
PAVL_NODE AvlTreeFindNode(IN PAVL_TREE Tree,
			  IN ULONG64 Key)
{
    assert(Tree != NULL);
    PAVL_NODE Node = Tree->BalancedRoot;
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
 * Insert tree node under Parent.
 */
VOID AvlTreeInsertNode(IN PAVL_TREE Tree,
		       IN PAVL_NODE Parent,
		       IN PAVL_NODE Node)
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
    AvlpSetParent(Node, Parent);

    /* Adjust balance and perform necessary rebalancing */
    AvlpSetBalance(Node, BALANCED);
    PAVL_NODE S = Parent;	/* S will point to node that needs rebalancing */
    PAVL_NODE N = Node;
    while (S != NULL) {
	SCHAR a;
	if (S->LeftChild == N) {
	    a = LEFT_HEAVY;
	} else {
	    assert(S->RightChild == N);
	    a = RIGHT_HEAVY;
	}
	SCHAR b = AvlpGetBalance(S);
	if (b == BALANCED) {
	    /* Tree just became unbalanced, but no rebalancing needed yet */
	    AvlpSetBalance(S, a);
	    /* Continue going up the tree */
	    N = S;
	    S = AvlGetParent(S);
	} else if (b == -a) {
	    /* Tree just became more balanced */
	    AvlpSetBalance(S, BALANCED);
	    /* No need to continue */
	    break;
	} else {		/* b == a */
	    /* Tree needs rebalancing */
	    AvlpTreeRebalanceNode(Tree, S);
	    /* No need to continue */
	    break;
	}
    }
}

/*
 * Simply unlink the Node from the given AVL Tree, without adjusting balance.
 * The Node is assumed to have at most one child.
 *
 * This function should never be called by anyone except AvlpTreeRemoveNode
 */
static VOID AvlpTreeSimpleRemove(IN PAVL_TREE Tree,
				 IN PAVL_NODE Node)
{
    assert(Node->LeftChild == NULL || Node->RightChild == NULL);
    PAVL_NODE Child = Node->LeftChild ? Node->LeftChild : Node->RightChild;
    PAVL_NODE Parent = AvlGetParent(Node);
    if (Child != NULL) {
	AvlpSetParent(Child, Parent);
    }
    if (Parent == NULL) {
	Tree->BalancedRoot = Child;
    } else {
	if (AvlIsRightChild(Node)) {
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
VOID AvlTreeRemoveNode(IN PAVL_TREE Tree,
		       IN PAVL_NODE Node)
{
    DbgTrace("Removing node %p (key %p) from tree %p\n",
	     Node, (PVOID)Node->Key, Tree);
    AvlDumpTree(Tree);

    PAVL_NODE DeleteNode = NULL;
    if ((Node->LeftChild == NULL) || (Node->RightChild == NULL)) {
	/* Case 1: Node has fewer than two children. Simply unlink the node. */
	DeleteNode = Node;
    } else {
	/* Case 2: Otherwise, check if one side is longer, and mark the immediate
	 * predecessor/successor for deletion. */
	if (AvlpGetBalance(Node) == RIGHT_HEAVY) {
	    /* Pick the successor which will be the longest side in this case */
	    DeleteNode = AvlGetNextNode(Node);
	} else {
	    /* Pick the predecessor which will be the longest side in this case */
	    DeleteNode = AvlGetNextNode(Node);
	}
    }

    /* Unlink the DeleteNode from the tree. Note that DeleteNode must have at
     * most one child. */
    assert(DeleteNode->LeftChild == NULL || DeleteNode->RightChild == NULL);
    PAVL_NODE ParentNode = AvlGetParent(DeleteNode);
    AVL_NODE_BALANCE Balance;
    if (ParentNode != NULL) {
	Balance = AvlIsLeftChild(DeleteNode) ? LEFT_HEAVY : RIGHT_HEAVY;
    }
    AvlpTreeSimpleRemove(Tree, DeleteNode);

    /* Rebalance the tree */
    while (ParentNode != NULL) {
        /* Check if the tree's balance increased */
        if (AvlpGetBalance(ParentNode) == Balance) {
            /* Now the tree is balanced */
            AvlpSetBalance(ParentNode, BALANCED);
        } else if (AvlpGetBalance(ParentNode) == BALANCED) {
            /* The tree has now become less balanced,
	     * since it was balanced before the deletion */
            AvlpSetBalance(ParentNode, -Balance);
            break;
	} else {
            /* The tree has become unbalanced, so a rebalance is needed */
            if (AvlpTreeRebalanceNode(Tree, ParentNode)) {
		break;
	    }
            /* Get the new parent after the balance */
            ParentNode = AvlGetParent(ParentNode);
	    /* ParentNode cannot be null since the tree still needs rebalancing
	     * (otherwise AvlpTreeRebalanceNode would have returned TRUE) */
	    assert(ParentNode != NULL);
        }

        /* Choose which balance factor to use based on which side we're on */
	if (AvlGetParent(ParentNode) != NULL) {
	    Balance = AvlIsRightChild(ParentNode) ? RIGHT_HEAVY : LEFT_HEAVY;
	}

        /* Iterate up the tree */
        ParentNode = AvlGetParent(ParentNode);
    }

    /* Check if this isn't the node we ended up deleting directly. If it is, we are done.
     * Otherwise we need to swap the DeleteNode with the Node that we actually want to
     * delete. */
    if (Node != DeleteNode) {
	DeleteNode->LeftChild = Node->LeftChild;
	DeleteNode->RightChild = Node->RightChild;
	if (Node->LeftChild != NULL) {
	    AvlpSetParent(Node->LeftChild, DeleteNode);
	}
	if (Node->RightChild != NULL) {
	    AvlpSetParent(Node->RightChild, DeleteNode);
	}
	DeleteNode->Parent = Node->Parent;
	if (AvlGetParent(Node) == NULL) {
	    Tree->BalancedRoot = DeleteNode;
	} else if (AvlIsRightChild(Node)) {
	    AvlGetParent(Node)->RightChild = DeleteNode;
	} else {
	    assert(AvlIsLeftChild(Node));
	    AvlGetParent(Node)->LeftChild = DeleteNode;
	}
	Node->LeftChild = Node->RightChild = NULL;
	Node->Parent = 0;
    }
    DbgTrace("After deletion\n");
    AvlDumpTree(Tree);
}

typedef struct _TRUNK {
    struct _TRUNK *Prev;
    char *Str;
} TRUNK, *PTRUNK;

// Helper function to print branches of the binary tree
static void AvlpTreeShowTrunks(PTRUNK p)
{
    if (p == NULL)
        return;

    AvlpTreeShowTrunks(p->Prev);

    if (p->Str != NULL) {
	DbgPrint("%s", p->Str);
    }
}

// Recursive function to print binary tree
// It uses inorder traversal
static void AvlpTreePrintTree(PAVL_NODE Root,
			      PTRUNK Prev,
			      BOOLEAN IsLeft)
{
    if (Root == NULL)
        return;

    char *PrevStr = "    ";
    TRUNK Trunk = { .Prev = Prev,
		    .Str = PrevStr };

    AvlpTreePrintTree(Root->LeftChild, &Trunk, TRUE);

    if (!Prev) {
        Trunk.Str = "---";
    } else if (IsLeft) {
        Trunk.Str = ".---";
        PrevStr = "   |";
    } else {
        Trunk.Str = "`---";
        Prev->Str = PrevStr;
    }

    AvlpTreeShowTrunks(&Trunk);
    CHAR c;
    if (AvlpGetBalance(Root) == BALANCED) {
	c = '|';
    } else if (AvlpGetBalance(Root) == LEFT_HEAVY) {
	c = '-';
    } else {
	assert(AvlpGetBalance(Root) == RIGHT_HEAVY);
	c = '+';
    }
    DbgPrint("%05llx%c\n", Root->Key >> PAGE_LOG2SIZE, c);

    if (Prev)
        Prev->Str = PrevStr;
    Trunk.Str = "   |";

    AvlpTreePrintTree(Root->RightChild, &Trunk, FALSE);
}

VOID AvlDumpTree(PAVL_TREE tree)
{
    AvlpTreePrintTree(tree->BalancedRoot, NULL, TRUE);
}

static VOID AvlpVisitTree(IN PAVL_NODE Node)
{
    DbgPrint("%p ", (PVOID) Node->Key);
}

VOID AvlVisitTreeLinear(PAVL_TREE Tree,
			PAVL_TREE_VISITOR Visitor)
{
    assert(Tree != NULL);
    assert(Visitor != NULL);
    PAVL_NODE Node = AvlGetFirstNode(Tree);
    while (Node != NULL) {
	Visitor(Node);
	Node = AvlGetNextNode(Node);
    }
}

VOID AvlDumpTreeLinear(PAVL_TREE Tree)
{
    AvlVisitTreeLinear(Tree, AvlpVisitTree);
}
