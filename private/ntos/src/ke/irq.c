#include "ki.h"

NTSTATUS KeCreateIrqHandlerEx(IN PIRQ_HANDLER IrqHandler,
			      IN MWORD IrqLine,
			      IN PCNODE CNode)
{
    assert(IrqHandler != NULL);
    MWORD Cap = 0;
    RET_ERR(MmAllocateCap(CNode, &Cap));
    assert(Cap != 0);
    int Error = seL4_IRQControl_Get(seL4_CapIRQControl, IrqLine,
				    CNode->TreeNode.Cap,
				    Cap, MmCNodeGetDepth(CNode));
    if (Error != 0) {
	MmDeallocateCap(CNode, Cap);
	KeDbgDumpIPCError(Error);
	return SEL4_ERROR(Error);
    }
    KeInitializeIrqHandler(IrqHandler, CNode, Cap, IrqLine);
    assert(Cap == IrqHandler->TreeNode.Cap);
    return STATUS_SUCCESS;
}

NTSTATUS KeConnectIrqNotification(IN PIRQ_HANDLER IrqHandler,
				  IN PNOTIFICATION Notification)
{
    assert(IrqHandler != NULL);
    assert(Notification != NULL);
    int Error = seL4_IRQHandler_SetNotification(IrqHandler->TreeNode.Cap,
						Notification->TreeNode.Cap);
    if (Error != 0) {
	KeDbgDumpIPCError(Error);
	return SEL4_ERROR(Error);
    }
    return STATUS_SUCCESS;
}
