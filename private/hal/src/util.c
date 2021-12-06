#include <halp.h>

/*
 * @implemented
 */
NTAPI PVOID MmPageEntireDriver(IN PVOID Address)
{
    PLDR_DATA_TABLE_ENTRY Module = NULL;
    NTSTATUS Status = LdrFindEntryForAddress(Address, &Module);
    if (!NT_SUCCESS(Status) || Module == NULL) {
	return NULL;
    }
    return Module->DllBase;
}

#ifndef NDEBUG
VOID _assert(PCSTR str, PCSTR file, unsigned int line)
{
    DbgPrint("Assertion %s failed at line %d of file %s\n",
	     str, line, file);
    /* Loop forever */
    while (1);
}
#else
VOID _assert(PCSTR str, PCSTR file, unsigned int line)
{
    /* Do nothing */
}
#endif

/*
 * For libsel4, required in both debug and release build.
 */
VOID __assert_fail(PCSTR str, PCSTR file, int line, PCSTR function)
{
    DbgPrint("Assertion %s failed in function %s at line %d of file %s\n",
	     str, function, line, file);
    /* Loop forever */
    while (1);
}

/*
 * Make a beep through the PC speaker. Returns TRUE is beep is successful.
 */
NTAPI BOOLEAN HalMakeBeep(IN ULONG Frequency)
{
    return NT_SUCCESS(HalpMakeBeep(Frequency));
}
