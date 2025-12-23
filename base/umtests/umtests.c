#include "umtests.h"

VOID TestDiskBench(IN UCHAR DriveLetter)
{
    VgaPrint("Benchmarking drive %c:\n", DriveLetter);
    if (DriveLetter < 'A' || DriveLetter > 'Z') {
	VgaPrint("Invalid drive letter 0x%x\n", DriveLetter);
	assert(FALSE);
	return;
    }
    CHAR Buffer[128] = {};
    snprintf(Buffer, sizeof(Buffer), "\\??\\%c:", DriveLetter);
    DiskBench(Buffer);
}

NTAPI VOID NtProcessStartup(PPEB Peb)
{
    TestNullDriver();
    TestBeepDriver(440, 1000);
    TestDiskBench('C');
}
