#include "umtests.h"

VOID BenchmarkDisk(IN ULONG DiskNumber)
{
    CHAR Path[512] = {};
    snprintf(Path, sizeof(Path), "\\Device\\Harddisk%d\\DR0", DiskNumber);
    VgaPrint("Benchmarking disk %s:\n", Path);
    DiskBench(Path, TRUE);
}

VOID BenchmarkVolume(IN UCHAR DriveLetter)
{
    VgaPrint("Benchmarking drive %c:\n", DriveLetter);
    if (DriveLetter < 'A' || DriveLetter > 'Z') {
       VgaPrint("Invalid drive letter 0x%x\n", DriveLetter);
       assert(FALSE);
       return;
    }
    CHAR Buffer[128] = {};
    snprintf(Buffer, sizeof(Buffer), "\\??\\%c:", DriveLetter);
    DiskBench(Buffer, FALSE);
}

NTAPI VOID NtProcessStartup(PPEB Peb)
{
    TestNullDriver();
    TestBeepDriver(440, 1000);
    BenchmarkDisk(0);
    BenchmarkVolume('C');
}
