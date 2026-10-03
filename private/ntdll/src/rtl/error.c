#include <ntdll.h>

/*
 * @implemented
 */
NTAPI NTSTATUS RtlSetThreadErrorMode(IN ULONG NewMode,
				     OUT PULONG OldMode OPTIONAL)
{
    PTEB Teb = NtCurrentTeb();

    /* Ignore invalid error modes */
    if (NewMode & ~(RTL_SEM_FAILCRITICALERRORS |
		    RTL_SEM_NOGPFAULTERRORBOX |
		    RTL_SEM_NOALIGNMENTFAULTEXCEPT)) {
	DPRINT1("Invalid error mode\n");
	return STATUS_INVALID_PARAMETER_1;
    }

    /* Return old mode */
    if (OldMode)
	*OldMode = Teb->HardErrorMode;

    /* Set new one and return success */
    Teb->HardErrorMode = NewMode;
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
ULONG NTAPI RtlGetThreadErrorMode(VOID)
{
    /* Return it from the TEB */
    return NtCurrentTeb()->HardErrorMode;
}
