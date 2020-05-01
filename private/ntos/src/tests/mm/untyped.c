#include "../tests.h"

extern MM_PHY_MEM MiPhyMemDescriptor;

VOID MmRunUntypedTests()
{
    DbgPrintFunc();
    PLIST_ENTRY SmallUntypedList = &MiPhyMemDescriptor.SmallUntypedList;
    DbgPrint("  Small free untyped:\n");
    LoopOverList(Untyped, SmallUntypedList, MM_UNTYPED, FreeListEntry) {
	DbgPrint("    cap = %d  log2(size) = %d\n", Untyped->TreeNode.Cap, Untyped->Log2Size);
    }
    PLIST_ENTRY MediumUntypedList = &MiPhyMemDescriptor.MediumUntypedList;
    DbgPrint("  Medium free untyped:\n");
    LoopOverList(Untyped, MediumUntypedList, MM_UNTYPED, FreeListEntry) {
	DbgPrint("    cap = %d  log2(size) = %d\n", Untyped->TreeNode.Cap, Untyped->Log2Size);
    }
    PLIST_ENTRY LargeUntypedList = &MiPhyMemDescriptor.LargeUntypedList;
    DbgPrint("  Large free untyped:\n");
    LoopOverList(Untyped, LargeUntypedList, MM_UNTYPED, FreeListEntry) {
	DbgPrint("    cap = %d  log2(size) = %d\n", Untyped->TreeNode.Cap, Untyped->Log2Size);
    }
}
