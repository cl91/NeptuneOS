#include <ntsvc.h>

static CAPSPACE_DESCRIPTOR MiCapSpaceDescriptor;
static CAPSPACE_CNODE_DESCRIPTOR MiInitCNodeDescriptor =
    {
     .CapSpace = &MiCapSpaceDescriptor,
     .Log2Size = CONFIG_ROOT_CNODE_SIZE_BITS,
     .FirstChild = NULL,
     .Policy = CAPSPACE_TYPE_TAIL_DEALLOC_ONLY
    };

static CAPSPACE_DESCRIPTOR MiCapSpaceDescriptor =
    {
     .Root = seL4_CapInitThreadCNode,
     .RootCNode = &MiInitCNodeDescriptor
    };

static void MiInitCapSpace()
{
    InitializeListHead(&MiInitCNodeDescriptor.SiblingList);
    MiInitCNodeDescriptor.FreeRange.StartCap = KeGetBootEnvironment()->InitialCapSpaceStart;
    MiInitCNodeDescriptor.FreeRange.Number = KeGetBootEnvironment()->InitialCapSpaceEnd
	- KeGetBootEnvironment()->InitialCapSpaceStart;
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
