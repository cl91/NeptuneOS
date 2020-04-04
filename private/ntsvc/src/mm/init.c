#include <ntsvc.h>
#include "mi.h"

/* FIXME: Only works for x86. Doesn't work for x64! */
void MmInitSystem()
{
    PBOOT_ENVIRONMENT BootEnvironment = KeGetBootEnvironment();
    seL4_SlotRegion UntypedCaps = BootEnvironment->BootInfo->untyped;
    MWORD InitUntyped = 0;
    LONG Log2Size = 128;

    /* Find the smallest untyped that is at least one large page */
    LoopOverUntyped(cap, desc, BootEnvironment) {
	if (!desc->isDevice && desc->sizeBits >= seL4_LargePageBits
	    && desc->sizeBits < Log2Size) {
	    InitUntyped = cap;
	    Log2Size = desc->sizeBits;
	}
    }

    /* Failing that, find at least 1 Page + 1 PageDirectory */
    if (InitUntyped == 0) {
	LoopOverUntyped(cap, desc, BootEnvironment) {
	    if (!desc->isDevice && desc->sizeBits >= (seL4_PageBits + 1)
		&& desc->sizeBits < Log2Size) {
		InitUntyped = cap;
		Log2Size = desc->sizeBits;
	    }
	}
    }

    /* If that also failed we are really out of options. Just die. */
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
	 .RootCNodeFreeCapStart = BootEnvironment->InitialCapSpaceStart,
	 .RootCNodeFreeCapNumber = BootEnvironment->InitialCapSpaceEnd - BootEnvironment->InitialCapSpaceStart
	};
    BUGCHECK_IF_ERR(MmRegisterClass(&InitInfo));
}
