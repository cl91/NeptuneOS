#pragma once

#include <nt.h>
#include <ntos.h>
#include <sel4/sel4.h>

#define KiAllocatePoolEx(Var, Type, OnError)				\
    ExAllocatePoolEx(Var, Type, sizeof(Type), NTOS_KE_TAG, OnError)
#define KiAllocatePool(Var, Type)	KiAllocatePoolEx(Var, Type, {})
#define KiAllocateArray(Var, Type, Size, OnError)			\
    ExAllocatePoolEx(Var, Type, sizeof(Type) * (Size), NTOS_KE_TAG, OnError)

static inline VOID KiInitializeIrqHandler(IN PIRQ_HANDLER Self,
					  IN PCNODE CSpace,
					  IN MWORD Cap,
					  IN MWORD Irq)
{
    assert(Self != NULL);
    assert(CSpace != NULL);
    MmInitializeCapTreeNode(&Self->TreeNode, CAP_TREE_NODE_IRQ_HANDLER, Cap,
			    CSpace, NULL);
    Self->Irq = Irq;
}

/* async.c */
VOID KiSignalDispatcherObject(IN PDISPATCHER_HEADER Dispatcher);

/* bugcheck.c */
VOID KiHaltSystem(IN PCSTR Format, ...);

#define HALT_IF_ERR(Expr)	{NTSTATUS Error = (Expr); if (!NT_SUCCESS(Error)) { \
	    KiHaltSystem("Unrecoverable error at %s @ %s line %d: Error Code 0x%x. System halted.\n", \
			 __func__, __FILE__, __LINE__, Error);}}

/* init.c */
ULONG KiProcessorCount;

/* services.c */
LIST_ENTRY KiReadyThreadList;
NTSTATUS KiInitExecutiveServices();
VOID KiDispatchExecutiveServices();

/* timer.c */
NTSTATUS KiEnableTimerInterruptService();

/* vga.c */
VOID KiInitVga();
