#pragma once

#include <nt.h>
#include <ntos.h>
#include <sel4/sel4.h>

#define KiAllocatePoolEx(Var, Type, OnError)				\
    ExAllocatePoolEx(Var, Type, sizeof(Type), NTOS_KE_TAG, OnError)
#define KiAllocatePool(Var, Type)	KiAllocatePoolEx(Var, Type, {})
#define KiAllocateArray(Var, Type, Size, OnError)			\
    ExAllocatePoolEx(Var, Type, sizeof(Type) * (Size), NTOS_KE_TAG, OnError)

typedef ULONG (*KI_DBG_PRINTER)(PCSTR Fmt, ...);

/* Helper function for dumping fault name */
static inline PCSTR KiDbgGetFaultName(IN seL4_Fault_t Fault)
{
    switch (seL4_Fault_get_seL4_FaultType(Fault)) {
    case seL4_Fault_NullFault:
	return "NULL-FAULT";
    case seL4_Fault_CapFault:
	return "CAP-FAULT";
    case seL4_Fault_UnknownSyscall:
	return "UNKNOWN-SYSCALL";
    case seL4_Fault_UserException:
	return "USER-EXCEPTION";
    case seL4_Fault_VMFault:
	return "VM-FAULT";
    }
    return "UNKNOWN-FAULT";
}

/* Helper function for dumping thread fault */
static inline VOID KiDbgDumpFault(IN seL4_Fault_t Fault,
				  IN KI_DBG_PRINTER DbgPrinter)
{
    switch (seL4_Fault_get_seL4_FaultType(Fault)) {
    case seL4_Fault_NullFault:
	DbgPrinter("NULL-FAULT\n");
	break;
    case seL4_Fault_CapFault:
	DbgPrinter("CAP-FAULT\n");
	break;
    case seL4_Fault_UnknownSyscall:
	DbgPrinter("UNKNOWN-SYSCALL\n");
	break;
    case seL4_Fault_UserException:
	DbgPrinter("USER-EXCEPTION\n");
	break;
    case seL4_Fault_VMFault:
	DbgPrinter("IP\t %p\tADDR\t%p\n"
		   "PREFETCH %p\tFSR\t%p\n",
		   (PVOID)seL4_Fault_VMFault_get_IP(Fault),
		   (PVOID)seL4_Fault_VMFault_get_Addr(Fault),
		   (PVOID)seL4_Fault_VMFault_get_PrefetchFault(Fault),
		   (PVOID)seL4_Fault_VMFault_get_FSR(Fault));
	break;
    default:
	DbgPrinter("WTF??? This should never happen.\n");
	break;
    }
}

/* async.c */
VOID KiSignalDispatcherObject(IN PDISPATCHER_HEADER Dispatcher);
SHORT KiDeliverApc(IN PTHREAD Thread,
		   IN ULONG MsgBufferEnd);

/* bugcheck.c */
NTSTATUS KiInitBugCheck();
VOID KiHaltSystem(IN PCSTR Format, ...);

#define HALT_IF_ERR(Expr)	{NTSTATUS Error = (Expr); if (!NT_SUCCESS(Error)) { \
	    KiHaltSystem("Unrecoverable error at %s @ %s line %d: Error Code 0x%x. System halted.\n", \
			 __func__, __FILE__, __LINE__, Error);}}

/* services.c */
IPC_ENDPOINT KiExecutiveServiceEndpoint;
LIST_ENTRY KiReadyThreadList;
NTSTATUS KiCreateEndpoint(IN PIPC_ENDPOINT Endpoint);
NTSTATUS KiInitExecutiveServices();
VOID KiDispatchExecutiveServices();

/* timer.c */
VOID KiSignalExpiredTimerList();
NTSTATUS KiInitTimer();

/* arch/debug.c */
VOID KiDumpThreadContext(IN PTHREAD_CONTEXT Context,
			 IN KI_DBG_PRINTER DbgPrinter);
