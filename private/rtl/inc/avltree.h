/*
 * Balanced (AVL) Tree
 *
 * This is an ALV tree implementation with a simplified interface that is used
 * by the NTOS root task and the client driver dll (wdm.dll). The AVL_TABLE data
 * structure in ntdll/rtl is exposed to the "user mode", while this is not.
 */

#pragma once

#include <ntdef.h>
#include <util.h>
#include <services.h>

/*
 * A tree node in the AVL tree
 */
typedef struct _AVL_NODE {
    ULONG64 Parent;
    struct _AVL_NODE *LeftChild;
    struct _AVL_NODE *RightChild;
    ULONG64 Key;	   /* Key is usually address or page number */
} AVL_NODE, *PAVL_NODE;

static inline VOID AvlInitializeNode(PAVL_NODE Node,
				     ULONG64 Key)
{
    Node->Parent = 0;
    Node->LeftChild = Node->RightChild = NULL;
    Node->Key = Key;
}

/*
 * AVL tree ordered by the key of the tree node
 */
typedef struct _AVL_TREE {
    PAVL_NODE BalancedRoot;
} AVL_TREE, *PAVL_TREE;

static inline VOID AvlInitializeTree(IN PAVL_TREE Tree)
{
    Tree->BalancedRoot = NULL;
}

static inline PAVL_NODE AvlGetParent(IN PAVL_NODE Node)
{
    ULONG64 ParentWord = Node->Parent;
    ParentWord &= ~((ULONG64) 0x3ULL);
    return (PAVL_NODE) ParentWord;
}

static inline BOOLEAN AvlIsRightChild(PAVL_NODE Node)
{
    PAVL_NODE Parent = AvlGetParent(Node);
    assert(Parent != NULL);
    return Parent->RightChild == Node;
}

static inline BOOLEAN AvlIsLeftChild(PAVL_NODE Node)
{
    PAVL_NODE Parent = AvlGetParent(Node);
    assert(Parent != NULL);
    return Parent->LeftChild == Node;
}

/*
 * Returns the next node in the AVL tree, ordered linearly.
 *
 * If Node is the last node in the tree, returns NULL.
 */
static inline PAVL_NODE AvlGetNextNode(IN PAVL_NODE Node)
{
    assert(Node != NULL);
    ULONG64 Key = Node->Key;
    if (Node->RightChild == NULL) {
	while (AvlGetParent(Node) != NULL) {
	    Node = AvlGetParent(Node);
	    assert(Node->Key != Key);
	    if (Node->Key > Key) {
		return Node;
	    }
	}
	return NULL;
    }
    Node = Node->RightChild;
    assert(Node != NULL);
    while (Node->LeftChild != NULL) {
	Node = Node->LeftChild;
    }
    return Node;
}

static inline PAVL_NODE AvlGetNextNodeSafe(IN PAVL_NODE Node)
{
    return Node ? AvlGetNextNode(Node) : NULL;
}

/*
 * Returns the previous node in the AVL tree, ordered linearly.
 *
 * If Node is the first node in the tree, returns NULL.
 */
static inline PAVL_NODE AvlGetPrevNode(IN PAVL_NODE Node)
{
    assert(Node != NULL);
    ULONG64 Key = Node->Key;
    if (Node->LeftChild == NULL) {
	while (AvlGetParent(Node) != NULL) {
	    Node = AvlGetParent(Node);
	    assert(Node->Key != Key);
	    if (Node->Key < Key) {
		return Node;
	    }
	}
	return NULL;
    }
    Node = Node->LeftChild;
    while (Node->RightChild != NULL) {
	Node = Node->RightChild;
    }
    return Node;
}

static inline PAVL_NODE AvlGetPrevNodeSafe(IN PAVL_NODE Node)
{
    return Node ? AvlGetPrevNode(Node) : NULL;
}

static inline BOOLEAN AvlTreeIsEmpty(IN PAVL_TREE Tree)
{
    assert(Tree != NULL);
    return Tree->BalancedRoot == NULL;
}

static inline PAVL_NODE AvlGetFirstNode(IN PAVL_TREE Tree)
{
    PAVL_NODE Node = Tree->BalancedRoot;
    if (Node == NULL) {
	return NULL;
    }
    while (Node->LeftChild != NULL) {
	Node = Node->LeftChild;
    }
    return Node;
}

static inline PAVL_NODE AvlGetLastNode(IN PAVL_TREE Tree)
{
    PAVL_NODE Node = Tree->BalancedRoot;
    if (Node == NULL) {
	return NULL;
    }
    while (Node->RightChild != NULL) {
	Node = Node->RightChild;
    }
    return Node;
}

/* avltree.c */
PAVL_NODE AvlTreeFindNodeOrParent(IN PAVL_TREE Tree,
				  IN ULONG64 Key);
PAVL_NODE AvlTreeFindNodeOrPrevEx(IN PAVL_TREE Tree,
				  IN ULONG64 Key,
				  OUT OPTIONAL PAVL_NODE *pParent);
PAVL_NODE AvlTreeFindNodeOrNextEx(IN PAVL_TREE Tree,
				  IN ULONG64 Key,
				  OUT OPTIONAL PAVL_NODE *pParent);
PAVL_NODE AvlTreeFindNode(IN PAVL_TREE Tree,
			  IN ULONG64 Key);
VOID AvlTreeAppendNode(IN PAVL_TREE Tree,
		       IN OUT PAVL_NODE Node,
		       IN ULONG64 Increment);
VOID AvlTreeInsertNode(IN PAVL_TREE Tree,
		       IN PAVL_NODE Parent,
		       IN PAVL_NODE Node);
VOID AvlTreeRemoveNode(IN PAVL_TREE Tree,
		       IN PAVL_NODE Node);
typedef VOID (*PAVL_TREE_VISITOR)(PAVL_NODE Node);
VOID AvlVisitTreeLinear(PAVL_TREE Tree,
			PAVL_TREE_VISITOR Visitor);
VOID AvlDumpTree(PAVL_TREE tree);
VOID AvlDumpTreeLinear(PAVL_TREE Tree);

FORCEINLINE PAVL_NODE AvlTreeFindNodeOrPrev(IN PAVL_TREE Tree,
					    IN MWORD Key)
{
    return AvlTreeFindNodeOrPrevEx(Tree, Key, NULL);
}

FORCEINLINE PAVL_NODE AvlTreeFindNodeOrNext(IN PAVL_TREE Tree,
					    IN MWORD Key)
{
    return AvlTreeFindNodeOrNextEx(Tree, Key, NULL);
}

/*
 * Returns TRUE if the supplied address is within the address range
 * specified by the address window
 */
static inline BOOLEAN AddrWindowContainsAddr(IN ULONG64 StartAddr,
					     IN ULONG64 WindowSize,
					     IN ULONG64 Addr)
{
    ULONG64 EndAddr = StartAddr + WindowSize;
    assert(EndAddr > StartAddr);
    return (Addr >= StartAddr) && (Addr < EndAddr);
}

/*
 * Returns TRUE if the supplied address is within the address range
 * specified by the AVL node's key value and the supplied window size
 */
static inline BOOLEAN AvlNodeContainsAddr(IN PAVL_NODE Node,
					  IN ULONG64 Size,
					  IN ULONG64 Addr)
{
    assert(Node != NULL);
    return AddrWindowContainsAddr(Node->Key, Size, Addr);
}

/*
 * Returns TRUE if the supplied address window has overlap with
 * the AVL node of the given size, ie. the intersection of the interval
 * [Node, Node+NodeSize) with the interval [Addr, Addr+WindowSize) is
 * non-empty.
 */
static inline BOOLEAN AvlNodeOverlapsAddrWindow(IN PAVL_NODE Node,
						IN ULONG64 NodeSize,
						IN ULONG64 Addr,
						IN ULONG64 WindowSize)
{
    assert(Node != NULL);
    return AvlNodeContainsAddr(Node, NodeSize, Addr) ||
	AvlNodeContainsAddr(Node, NodeSize, Addr + WindowSize - 1) ||
	AddrWindowContainsAddr(Addr, WindowSize, Node->Key) ||
	AddrWindowContainsAddr(Addr, WindowSize, Node->Key + NodeSize - 1);
}
