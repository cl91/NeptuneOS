#include "../tests.h"

extern VIRT_ADDR_SPACE MiNtosVaddrSpace;
extern PHY_MEM_DESCRIPTOR MiPhyMemDescriptor;

VOID MmRunAvlTreeTests()
{
    DbgPrint("mm: Running AVL tree tests...");
    PAVL_TREE RootUntypedTree = &MiPhyMemDescriptor.RootUntypedForest;
    DbgPrint("  RootUntypedTree:\n");
    AvlDumpTreeLinear(RootUntypedTree);
    AvlDumpTree(RootUntypedTree);
    PAVL_TREE VadTree = &MiNtosVaddrSpace.VadTree;
    DbgPrint("  VadTree:\n");
    AvlDumpTreeLinear(VadTree);
    AvlDumpTree(VadTree);
    PAVL_TREE PageTableTree = &MiNtosVaddrSpace.RootPagingStructure->SubStructureTree;
    DbgPrint("  PageTableTree:\n");
    AvlDumpTreeLinear(PageTableTree);
    AvlDumpTree(PageTableTree);
}
