#include <ntsvc.h>
#include <ctype.h>
#include "mi.h"

/* FIXME: Only works for x86. Doesn't work for x64! */
void MmInitSystem(PEPROCESS NtsvcProcess, seL4_BootInfo *bootinfo)
{
    seL4_SlotRegion UntypedCaps = bootinfo->untyped;
    MWORD InitUntyped = 0;
    LONG Log2Size = 128;

    /* Find at least 3 Page + 1 PageDirectory */
    LoopOverUntyped(cap, desc, bootinfo) {
	if (!desc->isDevice && desc->sizeBits >= (seL4_PageBits + 3)
	    && desc->sizeBits < Log2Size) {
	    InitUntyped = cap;
	    Log2Size = desc->sizeBits;
	}
    }
    if (InitUntyped == 0) {
	KeBugCheckMsg("Not enough memory. Check kernel config.");
    }

    MM_INIT_INFO_CLASS InitInfo =
	{
	 .InitVSpaceCap = seL4_CapInitThreadVSpace,
	 .InitUntypedCap = InitUntyped,
	 .InitUntypedLog2Size = Log2Size,
	 .RootCNodeCap = seL4_CapInitThreadCNode,
	 .RootCNodeLog2Size = CONFIG_ROOT_CNODE_SIZE_BITS,
	 .RootCNodeFreeCapStart = bootinfo->empty.start,
	 .RootCNodeFreeCapNumber = bootinfo->empty.end - bootinfo->empty.start,
	 .EProcess = NtsvcProcess
	};
    BUGCHECK_IF_ERR(MmRegisterClass(&InitInfo));

    LoopOverUntyped(cap, desc, bootinfo) {
	if (!desc->isDevice && cap != InitUntyped) {
	    MmRegisterRootUntyped(&NtsvcProcess->VaddrSpace, cap, desc->sizeBits);
	}
    }
}
