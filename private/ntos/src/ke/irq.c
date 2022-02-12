#include "ki.h"

NTSTATUS KeCreateIrqHandlerEx(IN PIRQ_HANDLER IrqHandler,
			      IN MWORD IrqLine,
			      IN PCNODE CSpace)
{
    assert(IrqHandler != NULL);
    MWORD Cap = 0;
    RET_ERR(MmAllocateCap(CSpace, &Cap));
    assert(Cap != 0);
    int Error = seL4_IRQControl_Get(seL4_CapIRQControl, IrqLine,
				    CSpace->TreeNode.Cap,
				    Cap, CSpace->Depth);
    if (Error != 0) {
	MmDeallocateCap(CSpace, Cap);
	KeDbgDumpIPCError(Error);
	return SEL4_ERROR(Error);
    }
    KeInitializeIrqHandler(IrqHandler, CSpace, Cap, IrqLine);
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
