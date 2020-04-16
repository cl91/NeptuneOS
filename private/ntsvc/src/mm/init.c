#include <ntsvc.h>
#include <ctype.h>
#include "mi.h"

/* FIXME: Only works for x86. Doesn't work for x64! */
NTSTATUS MmInitSystem(PEPROCESS NtsvcProcess, seL4_BootInfo *bootinfo)
{
    seL4_SlotRegion UntypedCaps = bootinfo->untyped;
    MWORD InitUntyped = 0;
    LONG Log2Size = 128;

    /* Find at least 7 Page + 1 PageDirectory */
    LoopOverUntyped(cap, desc, bootinfo) {
	if (!desc->isDevice && desc->sizeBits >= (seL4_PageBits + 3)
	    && desc->sizeBits < Log2Size) {
	    InitUntyped = cap;
	    Log2Size = desc->sizeBits;
	}
    }
    if (InitUntyped == 0) {
	return STATUS_NTOS_OUT_OF_MEMORY;
    }

    MM_INIT_INFO InitInfo =
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
    RET_IF_ERR(MmRegisterClass(&InitInfo));

    LoopOverUntyped(cap, desc, bootinfo) {
	if (!desc->isDevice && cap != InitUntyped) {
	    RET_IF_ERR(MmRegisterRootUntyped(&NtsvcProcess->VaddrSpace, cap,
					     desc->sizeBits));
	} else if (desc->isDevice && desc->sizeBits >= MM_PAGE_BITS) {
	    RET_IF_ERR(MmRegisterIoUntyped(&NtsvcProcess->VaddrSpace, cap,
					   desc->paddr, desc->sizeBits));
	}
    }

    return STATUS_SUCCESS;
}
