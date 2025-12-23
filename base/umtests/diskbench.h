#pragma once

#ifdef _WIN32

#include "umtests.h"

FORCEINLINE ULONGLONG GetCurrentTime()
{
    LARGE_INTEGER SystemTime;
    NtQuerySystemTime(&SystemTime);
    return SystemTime.QuadPart;
}

#else

#define _GNU_SOURCE
#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mount.h>
#include <fcntl.h>

// NT style typedefs
typedef unsigned char UCHAR;
typedef unsigned int ULONG;
typedef unsigned long long ULONGLONG;
typedef uint32_t UINT32;
typedef int NTSTATUS;
typedef void VOID, *HANDLE, *PVOID;
typedef const char *PCSTR;

#define STATUS_SUCCESS 0
#define STATUS_UNSUCCESSFUL (-1)
#define NT_SUCCESS(x) ((x) == STATUS_SUCCESS)
#define IN
#define OUT
#define TRUE (1)
#define FALSE (0)
#define FORCEINLINE static inline
#define PAGE_SIZE 4096
#define VgaPrint(...) printf(__VA_ARGS__)

FORCEINLINE NTSTATUS OpenVolume(IN PCSTR Path,
				OUT HANDLE *Handle)
{
    int Fd = syscall(SYS_openat, AT_FDCWD, Path, O_RDONLY | O_DIRECT, 0);
    if (Fd < 0)
        return STATUS_UNSUCCESSFUL;
    *Handle = (HANDLE)(uintptr_t)Fd;
    return STATUS_SUCCESS;
}

FORCEINLINE NTSTATUS ReadFile(IN HANDLE Handle,
			      OUT PVOID Buffer,
			      IN ULONG Length,
			      IN ULONGLONG Offset)
{
    int Fd = (int)(uintptr_t)Handle;

    // Linux O_DIRECT requires block alignment, so caller must align buffers
    if (syscall(SYS_lseek, Fd, (off_t)Offset, SEEK_SET) < 0)
        return -1;

    ssize_t Result = syscall(SYS_read, Fd, Buffer, Length);
    if (Result < 0)
        return STATUS_UNSUCCESSFUL;

    return STATUS_SUCCESS;
}

FORCEINLINE NTSTATUS GetFileSize(IN HANDLE FileHandle,
				 OUT ULONGLONG *FileSize)
{
    return syscall(SYS_ioctl, (int)(uintptr_t)FileHandle, BLKGETSIZE64, FileSize);
}

FORCEINLINE VOID NtClose(HANDLE Handle)
{
    syscall(SYS_close, (int)(uintptr_t)Handle);
}

/* Unit is in 100ns. */
FORCEINLINE ULONGLONG GetCurrentTime()
{
    struct timespec Ts;
    syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &Ts);
    return Ts.tv_sec * 10000000 + Ts.tv_nsec / 100;
}

#endif

FORCEINLINE UINT32 Rand32(IN OUT UINT32 *X)
{
    *X ^= *X << 13;
    *X ^= *X >> 17;
    *X ^= *X << 5;
    return *X;
}
