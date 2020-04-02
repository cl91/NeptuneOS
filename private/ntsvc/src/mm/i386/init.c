#include <nt.h>
#include <ntos.h>
#include <ntsvc.h>

/* Find an initial 4MiB space to map as the initial heap */
NTSTATUS MiMapInitialHeap()
{
    PBOOT_ENVIRONMENT BootEnvironment = KeGetBootEnvironment();
    seL4_SlotRegion UntypedCaps = BootEnvironment->BootInfo->untyped;
    UNTYPED_DESCRIPTOR UntypedDescs[(MWORD_BITS - seL4_LargePageBits + 1)*2] =
	{
	 {
	  .CapSpace = BootEnvironment->InitialCapSpace,
	  .Log2Size = MWORD_BITS,
	  .Split = FALSE
	 }
	};

    /* Find the smallest untyped that is at least one large page */
    LoopOverUntyped(cap, desc, BootEnvironment) {
	if (!desc->isDevice && desc->sizeBits >= seL4_LargePageBits
	    && desc->sizeBits < UntypedDescs[0].Log2Size) {
	    UntypedDescs[0].Cap = cap;
	    UntypedDescs[0].Log2Size = desc->sizeBits;
	}
    }

    /* Split the untyped until we have exactly one large page */
    LONG NumberSplits = UntypedDescs[0].Log2Size - seL4_LargePageBits;
    for (int i = 0; i < NumberSplits; i++) {
	BUGCHECK_IF_ERR(MmSplitUntyped(&UntypedDescs[2*i], &UntypedDescs[2*i+2], &UntypedDescs[2*i+3]));
    }
}

VOID MiInitMachineDependent()
{
    MiMapInitialHeap();
}
