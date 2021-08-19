#include "../tests.h"

extern VIRT_ADDR_SPACE MiNtosVaddrSpace;
extern PHY_MEM_DESCRIPTOR MiPhyMemDescriptor;

VOID MmRunAvlTreeTests()
{
    DbgPrint("mm: Running AVL tree tests...");
    PMM_AVL_TREE RootUntypedTree = &MiPhyMemDescriptor.RootUntypedForest;
    DbgPrint("  RootUntypedTree:\n");
    MmAvlDumpTreeLinear(RootUntypedTree);
    MmAvlDumpTree(RootUntypedTree);
    PMM_AVL_TREE VadTree = &MiNtosVaddrSpace.VadTree;
    DbgPrint("  VadTree:\n");
    MmAvlDumpTreeLinear(VadTree);
    MmAvlDumpTree(VadTree);
    PMM_AVL_TREE PageTableTree = &MiNtosVaddrSpace.RootPagingStructure->SubStructureTree;
    DbgPrint("  PageTableTree:\n");
    MmAvlDumpTreeLinear(PageTableTree);
    MmAvlDumpTree(PageTableTree);
}
