#pragma once

#include <nt.h>
#include <stdio.h>

#define DbgTrace(...) { DbgPrint("umtests %s(%d):  ", __func__, __LINE__); DbgPrint(__VA_ARGS__); }

/* device.c */
NTSTATUS TestNullDriver();
VOID TestBeepDriver(IN ULONG Freq,
		    IN ULONG Duration);

/* diskbench.c */
NTSTATUS DiskBench(IN PCSTR VolumePath);

/* file.c */
NTSTATUS OpenVolume(IN PCSTR Path,
		    OUT HANDLE *Handle);
NTSTATUS ReadFile(IN HANDLE Handle,
		  OUT PVOID Buffer,
		  IN ULONG Length,
		  IN ULONGLONG Offset);
NTSTATUS GetFileSize(IN HANDLE FileHandle,
		     OUT ULONGLONG *FileSize);

/* util.c */
VOID VgaPrint(IN PCSTR Fmt, ...) __attribute__((format(printf, 1, 2)));
