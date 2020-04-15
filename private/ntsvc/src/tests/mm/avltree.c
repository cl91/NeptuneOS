#include "../tests.h"

static int _print_t(PMM_AVL_NODE tree, int is_left, int offset, int depth, char s[20][255])
{
    char b[20];
    int width = 5;

    if (!tree) return 0;

    snprintf(b, sizeof(b), "(%03x)", tree->StartPageNum & 0xfff);

    int left  = _print_t(tree->LeftChild,  1, offset,                depth + 1, s);
    int right = _print_t(tree->RightChild, 0, offset + left + width, depth + 1, s);

#ifdef COMPACT
    for (int i = 0; i < width; i++)
        s[depth][offset + left + i] = b[i];

    if (depth && is_left) {

        for (int i = 0; i < width + right; i++)
            s[depth - 1][offset + left + width/2 + i] = '-';

        s[depth - 1][offset + left + width/2] = '.';

    } else if (depth && !is_left) {

        for (int i = 0; i < left + width; i++)
            s[depth - 1][offset - width/2 + i] = '-';

        s[depth - 1][offset + left + width/2] = '.';
    }
#else
    for (int i = 0; i < width; i++)
        s[2 * depth][offset + left + i] = b[i];

    if (depth && is_left) {

        for (int i = 0; i < width + right; i++)
            s[2 * depth - 1][offset + left + width/2 + i] = '-';

        s[2 * depth - 1][offset + left + width/2] = '+';
        s[2 * depth - 1][offset + left + width + right + width/2] = '+';

    } else if (depth && !is_left) {

        for (int i = 0; i < left + width; i++)
            s[2 * depth - 1][offset - width/2 + i] = '-';

        s[2 * depth - 1][offset + left + width/2] = '+';
        s[2 * depth - 1][offset - width/2 - 1] = '+';
    }
#endif

    return left + width + right;
}

static VOID PrintAvlTree(PMM_AVL_TREE tree)
{
    char s[20][255];
    for (int i = 0; i < 20; i++)
        snprintf(s[i], sizeof(s[0]), "%80s", " ");

    _print_t(tree->BalancedRoot, 0, 0, 0, s);

    for (int i = 0; i < 20; i++)
        DbgPrint("%s\n", s[i]);
}

static VOID PrintAvlTreeLinear(PMM_AVL_TREE tree)
{
    LoopOverList(Node, &tree->NodeList, MM_AVL_NODE, ListEntry) {
	DbgPrint("%p ", Node->StartPageNum);
    }
    DbgPrint("\n");
}
