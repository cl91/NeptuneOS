#include "ki.h"

NTSTATUS KeEnableIoPortX86(IN PCNODE CSpace,
			   IN USHORT PortNum,
			   IN PX86_IOPORT IoPort)
{
    assert(CSpace != NULL);
    assert(IoPort != NULL);
    MWORD Cap = 0;
    RET_ERR(MmAllocateCap(CSpace, &Cap));
    assert(Cap != 0);
    int Error = seL4_X86_IOPortControl_Issue(seL4_CapIOPortControl,
					     PortNum, PortNum,
					     CSpace->TreeNode.Cap,
					     Cap, CSpace->Depth);
    if (Error != 0) {
	MmDeallocateCap(CSpace, Cap);
	DbgTrace("seL4_X86_IOPortControl_Issue(0x%x, 0x%x, 0x%x, 0x%zx, 0x%zx, %d) failed\n",
		 seL4_CapIOPortControl, PortNum, PortNum,
		 CSpace->TreeNode.Cap, Cap, CSpace->Depth);
	KeDbgDumpIPCError(Error);
	return SEL4_ERROR(Error);
    }
    MmInitializeCapTreeNode(&IoPort->TreeNode,
			    CAP_TREE_NODE_X86_IOPORT,
			    Cap, CSpace, NULL);
    IoPort->PortNum = PortNum;
    return STATUS_SUCCESS;
}
