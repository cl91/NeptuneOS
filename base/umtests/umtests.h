#pragma once

#include <nt.h>
#include <stdio.h>

#define DbgTrace(...) { DbgPrint("umtests %s(%d):  ", __func__, __LINE__); DbgPrint(__VA_ARGS__); }

/* device.c */
NTSTATUS TestNullDriver();
VOID TestBeepDriver(IN ULONG Freq,
		    IN ULONG Duration);

/* file.c */
NTSTATUS TestFloppyDriver();

/* util.c */
VOID VgaPrint(IN PCSTR Fmt, ...);
