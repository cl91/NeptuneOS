#include <ntsvc.h>
#include "mi.h"

static CAPSPACE_DESCRIPTOR MiInitCapSpaceDescriptor;
static CAPSPACE_CNODE_DESCRIPTOR MiInitCNodeDescriptor =
    {
     .CapSpace = &MiInitCapSpaceDescriptor,
     .Log2Size = CONFIG_ROOT_CNODE_SIZE_BITS,
     .FirstChild = NULL,
     .Policy = CAPSPACE_TYPE_TAIL_DEALLOC_ONLY
    };

static CAPSPACE_DESCRIPTOR MiInitCapSpaceDescriptor =
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
    KeGetBootEnvironment()->InitialCapSpace = &MiInitCapSpaceDescriptor;
}

void MmInitSystem()
{
    MiInitCapSpace();
    MiInitMachineDependent();
}
