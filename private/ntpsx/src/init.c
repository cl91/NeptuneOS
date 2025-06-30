#include <ntdll.h>

PCSTR RtlpDbgTraceModuleName = "NTDLL";

static PPEB Peb;

static NTSTATUS LdrpInitializeProcess(PNTDLL_PROCESS_INIT_INFO InitInfo)
{
    /* Set up the image base address in the process environment block. */
    Peb->ImageBaseAddress = (PVOID)InitInfo->ImageBase;
    return STATUS_SUCCESS;
}

static NTSTATUS LdrpInitializeThread()
{
    DPRINT("LdrpInitializeThread() called for thread %p/%p\n",
	   NtCurrentTib()->ClientId.UniqueProcess,
	   NtCurrentTib()->ClientId.UniqueThread);
    return STATUS_SUCCESS;
}

static VOID LdrpInitialize(PNT_TIB NtTib)
{
    NtTib->Self = NtTib;
    NTSTATUS Status = STATUS_SUCCESS;
    PVOID IpcBuffer = seL4_GetIPCBuffer();
    /* Check if we have already setup the PEB. If not, we are the initial thread. */
    BOOLEAN InitThread = !Peb;
    if (InitThread) {
	/* At process startup the process init info is placed at the beginning
	 * of the ipc buffer. */
	NTDLL_PROCESS_INIT_INFO InitInfo = *((PNTDLL_PROCESS_INIT_INFO)(IpcBuffer));
	/* Now that the init info has been copied to the stack, clear the IPC buffer. */
	memset(IpcBuffer, 0, PAGE_SIZE);

	/* Set up the system service endpoint capability in the thread information block */
	NtTib->SystemServiceCap = InitInfo.ThreadInitInfo.SystemServiceCap;

	/* Set up the stack base and limit in the thread information block */
	NtTib->StackBase = (PVOID)InitInfo.ThreadInitInfo.StackTop;
	/* Note that since we have marked the stack of the initial thread as
	 * commit-on-demand, the stack limit should be the whole stack. */
	NtTib->StackLimit = (PVOID)(InitInfo.ThreadInitInfo.StackTop -
				    InitInfo.ThreadInitInfo.StackReserve);

	/* Set up the process environment block address in the thread environment block */
	Peb = ((PTEB)NtTib)->ProcessEnvironmentBlock = (PVOID)InitInfo.PebAddress;

	/* Initialize the Process */
	Status = LdrpInitializeProcess(&InitInfo);

	if (!NT_SUCCESS(Status)) {
	    goto err;
	}

	PsxProcessStartup();
    } else {
	/* At thread startup the thread init info is placed at the beginning
	 * of the ipc buffer. */
	NTDLL_THREAD_INIT_INFO InitInfo = *((PNTDLL_THREAD_INIT_INFO)(IpcBuffer));
	/* Now that the init info has been copied to the stack, clear the IPC buffer. */
	memset(IpcBuffer, 0, PAGE_SIZE);

	/* Set up the system service endpoint capability in the thread information block */
	NtTib->SystemServiceCap = InitInfo.SystemServiceCap;

	/* Set up the stack base and limit in the thread information block */
	NtTib->StackBase = (PVOID)InitInfo.StackTop;
	NtTib->StackLimit = (PVOID)(InitInfo.StackTop - InitInfo.StackReserve);

	/* Set up the process environment block address in the thread environment block.
	 * Note we need to do this for each thread. */
	((PTEB)NtTib)->ProcessEnvironmentBlock = Peb;

	/* This is a new thread initializing */
	Status = LdrpInitializeThread();

	/* Call thread entry point */
	PTHREAD_START_ROUTINE EntryPoint = NULL;
	PVOID Parameter = NULL;
	KeGetEntryPointFromThreadContext(&InitInfo.Context,
					 &EntryPoint, &Parameter);
	(*EntryPoint)(Parameter);
    }

    /* The thread entry point should never return. Shutdown the thread if it did.
     * If we are the init thread, also shutdown the entire process. */
    DPRINT1("LDR: Thread entry point returned for thread %p of process %p, "
	    "shutting down %s.\n", NtCurrentTib()->ClientId.UniqueThread,
	    NtCurrentTib()->ClientId.UniqueProcess, InitThread ? "process" : "thread");

err:
    /* Bail out if initialization has failed */
    if (!NT_SUCCESS(Status)) {
	HARDERROR_RESPONSE Response;

	/* Print a debug message */
	DPRINT1("LDR: Initialization failure for process %p thread %p. "
		"Image is %s; NTSTATUS = %08x\n",
		NtCurrentTib()->ClientId.UniqueProcess,
		NtCurrentTib()->ClientId.UniqueThread,
		RtlpDbgTraceModuleName, Status);

	/* Send HARDERROR_MSG LPC message to CSRSS */
	NtRaiseHardError(STATUS_APP_INIT_FAILURE, 1, 0,
			 (PULONG_PTR)&Status, OptionOk, &Response);

	if (InitThread) {
	    NtTerminateProcess(NtCurrentProcess(), STATUS_UNSUCCESSFUL);
	} else {
	    /* Raise a status to terminate the thread. */
	    NtTerminateThread(NtCurrentThread(), Status);
	}
    }
}

/*
 * This entry point serves both as the initial entry point for a
 * thread and as the entry point for an exception. The latter case
 * is distinguished by the second parameter being non-zero.
 */
VOID LdrInitializeThunk(PVOID Argument0,
			PVOID Argument1)
{
    if (Argument1) {
	KiDispatchUserException(Argument0, Argument1);
    } else {
	LdrpInitialize(Argument0);
    }
}
