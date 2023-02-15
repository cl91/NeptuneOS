#include "ki.h"

/* This is the system thread that listens to the fault endpoint
 * of the NT Executive event loop thread, in case the main event
 * loop thread of NTOS has faulted. For now we simply dump the
 * thread context and halt the system. In the future we will
 * initiate a debugger connection. */
static PSYSTEM_THREAD KiBugCheckThread;
static IPC_ENDPOINT KiExecutiveThreadFaultHandler;

static VOID KiPrintHaltMsg(PCSTR Format, va_list arglist)
{
    char buf[512];
    vsnprintf(buf, sizeof(buf), Format, arglist);
    HalDisplayString("\n\n");
    HalDisplayString(buf);
    HalDisplayString("\nFATAL ERROR. SYSTEM HALTED.\n");
#ifdef CONFIG_DEBUG_BUILD
    seL4_DebugPutString(buf);
    /* Dump some useful information. */
    seL4_DebugDumpScheduler();
#endif
}

VOID KiHaltSystem(IN PCSTR Format, ...)
{
    va_list arglist;
    va_start(arglist, Format);
    KiPrintHaltMsg(Format, arglist);
    va_end(arglist);

    /* Loop forever */
    while (1);
}

VOID KeBugCheck(IN PCSTR Function,
		IN PCSTR File,
		IN ULONG Line,
		IN ULONG Error)
{
    KiHaltSystem("Unrecoverable error at %s @ %s line %d: Error Code 0x%x.\n",
		 Function, File, Line, Error);
}

VOID KeBugCheckMsg(IN PCSTR Format, ...)
{
    va_list arglist;
    va_start(arglist, Format);
    KiPrintHaltMsg(Format, arglist);
    va_end(arglist);

    /* Loop forever */
    while (1);
}

static VOID KiDumpExecutiveThreadFault(IN seL4_Fault_t Fault,
				       IN KI_DBG_PRINTER DbgPrinter)
{
    DbgPrinter("\n==============================================================================\n"
		"Unhandled %s in thread NTOS Executive\n",
		KiDbgGetFaultName(Fault));
    KiDbgDumpFault(Fault, DbgPrinter);
    THREAD_CONTEXT Context;
    NTSTATUS Status = KeLoadThreadContext(seL4_CapInitThreadTCB, &Context);
    if (!NT_SUCCESS(Status)) {
	DbgPrinter("Unable to dump Executive thread context. Error 0x%08x\n", Status);
    }
    KiDumpThreadContext(&Context, DbgPrinter);
    DbgPrinter("==============================================================================\n");
}

/* Entry point of the bugcheck thread */
static VOID KiBugCheckSystem()
{
    while (TRUE) {
	seL4_MessageInfo_t Request = seL4_Recv(KiExecutiveThreadFaultHandler.TreeNode.Cap, NULL);
	seL4_Fault_t Fault = seL4_getFault(Request);
#ifdef CONFIG_DEBUG_BUILD
	KiDumpExecutiveThreadFault(Fault, DbgPrint);
#endif
	KiDumpExecutiveThreadFault(Fault, HalVgaPrint);
    }
}

static NTSTATUS KiSetThreadSpace(IN MWORD ThreadCap,
				 IN MWORD FaultEndpointCap,
				 IN PCNODE CSpace,
				 IN MWORD VSpaceCap)
{
    int Error = seL4_TCB_SetSpace(ThreadCap, FaultEndpointCap, CSpace->TreeNode.Cap,
				  seL4_CNode_CapData_new(0, MWORD_BITS - CSpace->Log2Size).words[0],
				  VSpaceCap, 0);

    if (Error != seL4_NoError) {
	return SEL4_ERROR(Error);
    }

    return STATUS_SUCCESS;
}

NTSTATUS KiInitBugCheck()
{
    extern CNODE MiNtosCNode;
    KiBugCheckThread = (PSYSTEM_THREAD)ExAllocatePoolWithTag(sizeof(SYSTEM_THREAD),
							     NTOS_KE_TAG);
    if (KiBugCheckThread == NULL) {
	return STATUS_NO_MEMORY;
    }
    RET_ERR(PsCreateSystemThread(KiBugCheckThread, "NTOS Bugcheck", KiBugCheckSystem, TRUE));
    RET_ERR(KiCreateEndpoint(&KiExecutiveThreadFaultHandler));
    RET_ERR(KiSetThreadSpace(seL4_CapInitThreadTCB, KiExecutiveThreadFaultHandler.TreeNode.Cap,
			     &MiNtosCNode, seL4_CapInitThreadVSpace));
    RET_ERR(PsResumeSystemThread(KiBugCheckThread));
    return STATUS_SUCCESS;
}
