/*
 * COPYRIGHT:         See COPYING in the top level directory
 * PROJECT:           ReactOS system libraries
 * PURPOSE:           Rtl user thread functions
 * FILE:              lib/rtl/i386/thread.c
 * PROGRAMERS:
 *                    Alex Ionescu (alex@relsoft.net)
 *                    Eric Kohl
 *                    KJK::Hyperion
 */

/* INCLUDES *****************************************************************/

#include <ntdll.h>

/* PRIVATE FUNCTIONS *******************************************************/

/*
 * @implemented
 */
NTAPI VOID RtlInitializeContext(IN HANDLE ProcessHandle,
				OUT PCONTEXT ThreadContext,
				IN PVOID ThreadStartParam OPTIONAL,
				IN PTHREAD_START_ROUTINE ThreadStartAddress,
				IN PINITIAL_TEB InitialTeb)
{
    DPRINT("RtlInitializeContext: (hProcess: %p, ThreadContext: %p, Teb: %p\n",
	   ProcessHandle, ThreadContext, InitialTeb);

    /*
     * Set the Initial Registers
     * This is based on NT's default values -- crazy apps might expect this...
     */
    ThreadContext->Ebp = 0;
    ThreadContext->Eax = 0;
    ThreadContext->Ebx = 1;
    ThreadContext->Ecx = 2;
    ThreadContext->Edx = 3;
    ThreadContext->Esi = 4;
    ThreadContext->Edi = 5;

    /* Set the Selectors */
    ThreadContext->SegGs = 0;
    ThreadContext->SegFs = (ULONG) NtCurrentTeb();
    ThreadContext->SegEs = 0;
    ThreadContext->SegDs = 0;
    ThreadContext->SegSs = 0;
    ThreadContext->SegCs = 0;

    /* Enable Interrupts */
    ThreadContext->EFlags = EFLAGS_INTERRUPT_MASK;

    /* Settings passed */
    ThreadContext->Eip = (ULONG) ThreadStartAddress;
    ThreadContext->Esp = (ULONG) InitialTeb;

    /* Only the basic Context is initialized */
    ThreadContext->ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS;

    /* Set up ESP to the right value */
    ThreadContext->Esp -= sizeof(PVOID);
    NtWriteVirtualMemory(ProcessHandle,
			 (PVOID) ThreadContext->Esp,
			 (PVOID) & ThreadStartParam, sizeof(PVOID), NULL);

    /* Push it down one more notch for RETEIP */
    ThreadContext->Esp -= sizeof(PVOID);
}
