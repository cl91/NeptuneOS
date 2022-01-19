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

    /* Initialize everything to 0 */
    RtlZeroMemory(ThreadContext, sizeof(*ThreadContext));

    /* Set the Selectors */
    ThreadContext->SegFs = (ULONG) NtCurrentTeb();

    /* Enable Interrupts */
    ThreadContext->EFlags = EFLAGS_INTERRUPT_MASK;

    /* Set start parameter. We pass the thread start parameter in the first
     * fastcall registry. See ntdll/ldr/init.c */
    ThreadContext->Ecx = (ULONG)ThreadStartParam;

    /* Pass the thread start address in EIP */
    ThreadContext->Eip = (ULONG) ThreadStartAddress;

    /* Only the basic Context is initialized */
    ThreadContext->ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS;
}
