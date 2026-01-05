#include "ki.h"
#include "ntdef.h"

/* This is the system thread that listens to the fault endpoint
 * of the NT Executive event loop thread, in case the main event
 * loop thread of NTOS has faulted. For now we simply dump the
 * thread context and halt the system. In the future we will
 * initiate a debugger connection. */
static PSYSTEM_THREAD KiBugCheckThread;
static IPC_ENDPOINT KiExecutiveThreadFaultHandler;

NTSTATUS KeSetThreadPriority(IN MWORD ThreadCap,
			     IN THREAD_PRIORITY Priority)
{
    assert(ThreadCap != 0);
    int Error = seL4_TCB_SetPriority(ThreadCap, NTOS_TCB_CAP, Priority);

    if (Error != 0) {
	DbgTrace("seL4_TCB_SetPriority failed for thread cap 0x%zx with error %d\n",
		 ThreadCap, Error);
	return SEL4_ERROR(Error);
    }
    return STATUS_SUCCESS;
}

static VOID KiNotifyDrivers()
{
    LoopOverList(Driver, &IoBugcheckNotificationList,
		 IO_DRIVER_OBJECT, BugcheckNotificationLink) {
	if (Driver->BugcheckNotification.TreeNode.Cap) {
	    seL4_Signal(Driver->BugcheckNotification.TreeNode.Cap);
	} else {
	    char Buf[256];
	    snprintf(Buf, sizeof(Buf),
		     "Driver object %s has null bugcheck notification cap.\n",
		     IODBG_DRIVER_FILENAME(Driver));
	    HalDisplayString(Buf);
	}
    }
}

static VOID KiWriteBugcheckMsg(IN PCSTR String)
{
    PKUSER_SHARED_DATA Data = PsGetUserSharedData();
    if (Data) {
	RtlAppendStringBuffer(String, &Data->BugcheckMsgLength,
			      Data->BugcheckMsg, sizeof(Data->BugcheckMsg));
    }
}

static ULONG KiPrintBugcheckMsg(IN PCSTR Format, ...)
{
    va_list arglist;
    va_start(arglist, Format);
    char Buf[512];
    vsnprintf(Buf, sizeof(Buf), Format, arglist);
    KiWriteBugcheckMsg(Buf);
    va_end(arglist);
    return 0;
}

static VOID KiPrintHaltMsg(PCSTR Format, va_list arglist)
{
    char Buf[512];
    vsnprintf(Buf, sizeof(Buf), Format, arglist);
    HalDisplayString("\n\n");
    HalDisplayString(Buf);
    HalDisplayString("\nFATAL ERROR. SYSTEM HALTED.\n");
    KiWriteBugcheckMsg(Buf);
#ifdef CONFIG_DEBUG_BUILD
    seL4_DebugPutString(Buf);
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
    KiNotifyDrivers();
    __builtin_trap();

    /* Loop forever */
    while (1) {
	seL4_Yield();
    }
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
    KiNotifyDrivers();
    __builtin_trap();

    /* Loop forever */
    while (1) {
	seL4_Yield();
    }
}

static VOID KiDumpExecutiveThreadFault(IN seL4_Fault_t Fault,
				       IN KI_DBG_PRINTER DbgPrinter)
{
    DbgPrinter("\n==============================================================================\n"
		"Unhandled %s in thread NTOS Executive\n",
		KiDbgGetFaultName(Fault));
    KiDbgDumpFault(Fault, DbgPrinter);
    THREAD_CONTEXT Context;
    NTSTATUS Status = KeLoadThreadContext(NTOS_TCB_CAP, &Context);
    if (!NT_SUCCESS(Status)) {
	DbgPrinter("Unable to dump Executive thread context. Error 0x%08x\n", Status);
    }
    KiDumpThreadContext(&Context, DbgPrinter);
    DbgPrinter("Stack:\n");
#ifdef _M_IX86
    PULONG_PTR Stack = (PULONG_PTR)Context.esp;
    for (ULONG i = 0; i < 0x40; i++) {
	DbgPrinter("%08x", Stack[i]);
	if ((i & 0x7) == 0x7) {
	    DbgPrinter("\n");
	} else {
	    DbgPrinter(" ");
	}
    }
#elif defined(_M_AMD64)
    PULONG_PTR Stack = (PULONG_PTR)Context.rsp;
    for (ULONG i = 0; i < 0x20; i++) {
	DbgPrinter("%016x", Stack[i]);
	if ((i & 0x3) == 0x3) {
	    DbgPrinter("\n");
	} else {
	    DbgPrinter(" ");
	}
    }
#endif
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
	KiDumpExecutiveThreadFault(Fault, KiPrintBugcheckMsg);
	KiNotifyDrivers();
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
    C_ASSERT((ULONG)BUGCHECK_LEVEL == seL4_MaxPrio);
    extern CNODE MiNtosCNode;
    KiBugCheckThread = (PSYSTEM_THREAD)ExAllocatePoolWithTag(sizeof(SYSTEM_THREAD),
							     NTOS_KE_TAG);
    if (KiBugCheckThread == NULL) {
	return STATUS_NO_MEMORY;
    }
    RET_ERR(PsCreateSystemThread(KiBugCheckThread, "NTOS Bugcheck", KiBugCheckSystem, TRUE));
    RET_ERR(KeCreateEndpoint(&KiExecutiveThreadFaultHandler));
    RET_ERR(KiSetThreadSpace(NTOS_TCB_CAP, KiExecutiveThreadFaultHandler.TreeNode.Cap,
			     &MiNtosCNode, seL4_CapInitThreadVSpace));
    RET_ERR(PsSetSystemThreadPriority(KiBugCheckThread, BUGCHECK_LEVEL));
    RET_ERR(PsResumeSystemThread(KiBugCheckThread));
    return STATUS_SUCCESS;
}
