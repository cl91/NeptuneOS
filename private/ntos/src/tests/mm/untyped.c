#include "../tests.h"

VOID MmRunUntypedTests()
{
    DbgPrintFunc();
    PLIST_ENTRY RootUntypedList = &ExNtosProcess.VaddrSpace.RootUntypedList;
    DbgPrint("  Root untyped:\n");
    LoopOverList(Untyped, RootUntypedList, MM_UNTYPED, RootListEntry) {
	DbgPrint("    cap = %d  log2(size) = %d\n", Untyped->TreeNode.Cap, Untyped->Log2Size);
    }
    PLIST_ENTRY SmallUntypedList = &ExNtosProcess.VaddrSpace.SmallUntypedList;
    DbgPrint("  Small free untyped:\n");
    LoopOverList(Untyped, SmallUntypedList, MM_UNTYPED, FreeListEntry) {
	DbgPrint("    cap = %d  log2(size) = %d\n", Untyped->TreeNode.Cap, Untyped->Log2Size);
    }
    PLIST_ENTRY MediumUntypedList = &ExNtosProcess.VaddrSpace.MediumUntypedList;
    DbgPrint("  Medium free untyped:\n");
    LoopOverList(Untyped, MediumUntypedList, MM_UNTYPED, FreeListEntry) {
	DbgPrint("    cap = %d  log2(size) = %d\n", Untyped->TreeNode.Cap, Untyped->Log2Size);
    }
    PLIST_ENTRY LargeUntypedList = &ExNtosProcess.VaddrSpace.LargeUntypedList;
    DbgPrint("  Large free untyped:\n");
    LoopOverList(Untyped, LargeUntypedList, MM_UNTYPED, FreeListEntry) {
	DbgPrint("    cap = %d  log2(size) = %d\n", Untyped->TreeNode.Cap, Untyped->Log2Size);
    }
}
