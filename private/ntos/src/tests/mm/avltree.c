#include "../tests.h"

typedef struct _TRUNK
{
    struct _TRUNK *Prev;
    char *Str;
} TRUNK, *PTRUNK;

// Helper function to print branches of the binary tree
static void ShowTrunks(PTRUNK p)
{
    if (p == NULL)
        return;

    ShowTrunks(p->Prev);

    if (p->Str != NULL) {
	DbgPrint("%s", p->Str);
    }
}

// Recursive function to print binary tree
// It uses inorder traversal
static void PrintTree(PMM_AVL_NODE Root,
		      PTRUNK Prev,
		      BOOLEAN IsLeft)
{
    if (Root == NULL)
        return;
    
    char *PrevStr = "    ";
    TRUNK Trunk = { .Prev = Prev,
		    .Str = PrevStr };

    PrintTree(Root->LeftChild, &Trunk, TRUE);

    if (!Prev) {
        Trunk.Str = "---";
    } else if (IsLeft) {
        Trunk.Str = ".---";
        PrevStr = "   |";
    } else {
        Trunk.Str = "`---";
        Prev->Str = PrevStr;
    }

    ShowTrunks(&Trunk);
    DbgPrint("%05x\n", Root->Key);

    if (Prev)
        Prev->Str = PrevStr;
    Trunk.Str = "   |";

    PrintTree(Root->RightChild, &Trunk, FALSE);
}

static VOID PrintAvlTree(PMM_AVL_TREE tree)
{
    PrintTree(tree->BalancedRoot, NULL, TRUE);
}

static VOID PrintAvlTreeLinear(PMM_AVL_TREE tree)
{
    LoopOverList(Node, &tree->NodeList, MM_AVL_NODE, ListEntry) {
	DbgPrint("%05x ", Node->Key);
    }
    DbgPrint("\n");
}

extern MM_VADDR_SPACE MiNtosVaddrSpace;

VOID MmRunAvlTreeTests()
{
    DbgPrintFunc();
    PMM_AVL_TREE RootIoUntypedTree = &MiNtosVaddrSpace.RootIoUntypedTree;
    DbgPrint("  RootIoUntypedTree:\n");
    PrintAvlTreeLinear(RootIoUntypedTree);
    PrintAvlTree(RootIoUntypedTree);
    PMM_AVL_TREE VadTree = &MiNtosVaddrSpace.VadTree;
    DbgPrint("  VadTree:\n");
    PrintAvlTreeLinear(VadTree);
    PrintAvlTree(VadTree);
    PMM_AVL_TREE PageTableTree = &MiNtosVaddrSpace.PageTableTree;
    DbgPrint("  PageTableTree:\n");
    PrintAvlTreeLinear(PageTableTree);
    PrintAvlTree(PageTableTree);
}
