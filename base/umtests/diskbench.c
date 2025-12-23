#include "diskbench.h"

#define RANDOM_IO_SIZE   4096
#define RANDOM_IO_COUNT  10000
#define SEQ_IO_SIZE      (1024 * 1024)
#define SEQ_IO_COUNT     256
#define SECTOR_SIZE      4096

static UCHAR RandomBuffer[RANDOM_IO_SIZE] __attribute__((aligned(PAGE_SIZE)));
static UCHAR SeqBuffer[SEQ_IO_SIZE] __attribute__((aligned(PAGE_SIZE)));

NTSTATUS DiskBench(IN PCSTR VolumePath)
{
    HANDLE VolumeHandle = NULL;
    NTSTATUS Status = OpenVolume(VolumePath, &VolumeHandle);
    if (!NT_SUCCESS(Status)) {
        VgaPrint("Failed to open volume %s, error 0x%x\n", VolumePath, Status);
        return Status;
    }

    ULONGLONG VolumeSize = 0;
    Status = GetFileSize(VolumeHandle, &VolumeSize);
    if (!NT_SUCCESS(Status)) {
	VgaPrint("Failed to query file length for %s, error 0x%x\n",
		 VolumePath, Status);
	return Status;
    }
    assert(RANDOM_IO_SIZE < SEQ_IO_SIZE);
    if (VolumeSize < SEQ_IO_SIZE) {
	VgaPrint("Volume size too small (got 0x%llx, need 0x%x)\n",
		 VolumeSize, SEQ_IO_SIZE);
	return STATUS_UNSUCCESSFUL;
    }
    ULONGLONG MaxOffset = VolumeSize - RANDOM_IO_SIZE;

    // -----------------------------
    // Random 4K reads
    // -----------------------------
    UINT32 Seed = 0xC0FEFE;
    ULONGLONG StartTime, EndTime;
    StartTime = GetCurrentTime();

    for (ULONG i = 0; i < RANDOM_IO_COUNT; i++) {
        ULONGLONG Offset = ((ULONGLONG)Rand32(&Seed) * RANDOM_IO_SIZE) %
                           (1024ULL * 1024ULL * 1024ULL); // 1GB window
	Offset = Offset % MaxOffset;
	Offset &= ~(SECTOR_SIZE - 1);

        Status = ReadFile(VolumeHandle, RandomBuffer, RANDOM_IO_SIZE, Offset);
	if (!NT_SUCCESS(Status)) {
	    VgaPrint("Failed to read volume file, offset 0x%llx, buffer size 0x%x\n",
		     Offset, RANDOM_IO_SIZE);
	}
    }

    EndTime = GetCurrentTime();

    ULONGLONG RandomTimeMs = (EndTime - StartTime) / 10000;
    ULONGLONG RandomMBpsX100 = (RANDOM_IO_COUNT * RANDOM_IO_SIZE * 1000ULL * 100ULL) /
	(RandomTimeMs * 1024ULL * 1024ULL);
    VgaPrint("Random %dK Reads: %llu.%02llu MB/s (%llu.%03llu seconds)\n",
	     RANDOM_IO_SIZE / 1024,
	     RandomMBpsX100 / 100, RandomMBpsX100 % 100,
	     RandomTimeMs / 100, RandomTimeMs % 100);

    // -----------------------------
    // Sequential 1MB reads
    // -----------------------------
    StartTime = GetCurrentTime();

    ULONGLONG Offset = 0;
    for (ULONG i = 0; i < SEQ_IO_COUNT; i++) {
        ReadFile(VolumeHandle, SeqBuffer, SEQ_IO_SIZE, Offset);
        Offset += SEQ_IO_SIZE;
    }

    EndTime = GetCurrentTime();


    ULONGLONG SeqTimeMs = (EndTime - StartTime) / 10000;
    ULONGLONG SeqMBpsX100 = (SEQ_IO_COUNT * SEQ_IO_SIZE * 1000ULL * 100ULL) /
	(SeqTimeMs * 1024ULL * 1024ULL);
    VgaPrint("Sequential %dMB Reads: %llu.%02llu MB/s (%llu.%03llu seconds)\n",
	     SEQ_IO_SIZE / (1024 * 1024),
	     SeqMBpsX100 / 100, SeqMBpsX100 % 100,
	     SeqTimeMs / 100, SeqTimeMs % 100);

    NtClose(VolumeHandle);
    return STATUS_SUCCESS;
}

#ifndef _WIN32

int main(int Argc, char **Argv)
{
    if (Argc < 2) {
        printf("Usage: diskbench <device>\n");
        printf("Example: diskbench /dev/sda\n");
        return 1;
    }

    const char *VolumePath = Argv[1];
    return DiskBench(VolumePath);
}

#endif
