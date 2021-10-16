#include <hal.h>

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
