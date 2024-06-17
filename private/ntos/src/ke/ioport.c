#include "ki.h"

NTSTATUS KeEnableIoPortEx(IN PCNODE CSpace,
			  IN USHORT PortNum,
			  IN USHORT Count,
			  IN PX86_IOPORT IoPort)
{
    assert(CSpace != NULL);
    assert(IoPort != NULL);
    MWORD Cap = 0;
    RET_ERR(MmAllocateCap(CSpace, &Cap));
    assert(Cap != 0);
    int Error = seL4_X86_IOPortControl_Issue(seL4_CapIOPortControl,
					     PortNum, PortNum + Count - 1,
					     CSpace->TreeNode.Cap,
					     Cap, CSpace->Depth);
    if (Error != 0) {
	MmDeallocateCap(CSpace, Cap);
	DbgTrace("seL4_X86_IOPortControl_Issue(0x%x, 0x%x, 0x%x, 0x%zx, 0x%zx, %d) failed\n",
		 seL4_CapIOPortControl, PortNum, PortNum + Count - 1,
		 CSpace->TreeNode.Cap, Cap, CSpace->Depth);
	KeDbgDumpIPCError(Error);
	return SEL4_ERROR(Error);
    }
    MmInitializeCapTreeNode(&IoPort->TreeNode,
			    CAP_TREE_NODE_X86_IOPORT,
			    Cap, CSpace, NULL);
    IoPort->PortNum = PortNum;
    IoPort->Count = Count;
    return STATUS_SUCCESS;
}

NTSTATUS KeReadPort8(IN PX86_IOPORT Port,
		     OUT UCHAR *Out)
{
    assert(Out != NULL);
    seL4_X86_IOPort_In8_t Reply = seL4_X86_IOPort_In8(Port->TreeNode.Cap,
						      Port->PortNum);
    if (Reply.error != 0) {
	DbgTrace("Reading IO port 0x%x (cap 0x%zx) failed with error %d\n",
		 Port->PortNum, Port->TreeNode.Cap, Reply.error);
	KeDbgDumpIPCError(Reply.error);
	return SEL4_ERROR(Reply.error);
    }
    *Out = Reply.result;
    return STATUS_SUCCESS;
}

NTSTATUS KeWritePort8(IN PX86_IOPORT Port,
		      IN UCHAR Data)
{
    int Error = seL4_X86_IOPort_Out8(Port->TreeNode.Cap, Port->PortNum, Data);
    if (Error != 0) {
	DbgTrace("Writing IO port 0x%x (cap 0x%zx) with data 0x%x failed with error %d\n",
		 Port->PortNum, Port->TreeNode.Cap, Data, Error);
	KeDbgDumpIPCError(Error);
	return SEL4_ERROR(Error);
    }
    return STATUS_SUCCESS;
}
