#include <ntsvc.h>

CAPSPACE_DESCRIPTOR MiCapSpaceDescriptor;

static void MiInitCapSpace()
{
    MiCapSpaceDescriptor.Root = KeGetBootEnvironment()->InitialCapSpaceRoot;
    MiCapSpaceDescriptor.Log2Size = CONFIG_ROOT_CNODE_SIZE_BITS;
    MiCapSpaceDescriptor.TotalLevels = 1;
    InitializeListHead(&MiCapSpaceDescriptor.FreeList.ListEntry);
    MiCapSpaceDescriptor.FreeList.Start = KeGetBootEnvironment()->InitialCapSpaceStart;
    MiCapSpaceDescriptor.FreeList.Number = KeGetBootEnvironment()->InitialCapSpaceEnd - KeGetBootEnvironment()->InitialCapSpaceStart;
}

void MmInitSystem()
{
    MiInitCapSpace();
    UNTYPED_DESCRIPTOR Src, Dest1, Dest2;
    seL4_UntypedDesc *Desc = &KeGetBootEnvironment()->BootInfo->untypedList[0];
    Src.CapSpace = &MiCapSpaceDescriptor;
    Src.Cap = KeGetBootEnvironment()->BootInfo->untyped.start;
    Src.Log2Size = Desc->sizeBits;
    Src.Split = FALSE;
    DbgPrint("Status = %zx\n", MmSplitUntyped(&Src, &Dest1, &Dest2));
}

