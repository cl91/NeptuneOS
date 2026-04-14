#include "ki.h"

NTSTATUS KeCreateIrqHandlerCapEx(IN OUT PIRQ_HANDLER IrqHandler,
				 IN PCNODE CNode)
{
    assert(IrqHandler != NULL);
    MWORD Cap = 0;
    RET_ERR(MmAllocateCap(CNode, &Cap));
    assert(Cap != 0);
    NTSTATUS Status = HalGetIrqCap(IrqHandler, CNode->TreeNode.Cap,
				   Cap, MmCNodeGetDepth(CNode));
    if (!NT_SUCCESS(Status)) {
	MmDeallocateCap(CNode, Cap);
	return Status;
    }
    MmInitializeCapTreeNode(&IrqHandler->TreeNode, CAP_TREE_NODE_IRQ_HANDLER, Cap,
			    CNode, NULL);
    assert(Cap == IrqHandler->TreeNode.Cap);
    return STATUS_SUCCESS;
}

VOID KeDestroyIrqHandler(IN OUT PIRQ_HANDLER IrqHandler)
{
    assert(IrqHandler != NULL);
    assert(!MmCapTreeNodeHasChildren(&IrqHandler->TreeNode));
    /* Detach the cap node from the cap derivation tree and release its
     * parent untyped (if any) */
    MmCapTreeDeleteNode(&IrqHandler->TreeNode);
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
