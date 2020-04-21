#pragma once

#include <nt.h>
#include <wchar.h>

/* Returns Ceil(x/y) for unsigned integers x and y */
#define RtlDivCeilUnsigned(x,y)	(((x)+(y)-1)/(y))

VOID NTAPI RtlInitUnicodeString(IN OUT PUNICODE_STRING DestinationString,
				IN PCWSTR SourceString);

NTSTATUS NTAPI RtlInitUnicodeStringEx(OUT PUNICODE_STRING DestinationString,
				      IN PCWSTR SourceString);
